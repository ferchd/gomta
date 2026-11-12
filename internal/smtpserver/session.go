package smtpserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/textproto"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/ferchd/gomta/config"
	"github.com/ferchd/gomta/internal/auth"
	"github.com/ferchd/gomta/plugin"
	"github.com/ferchd/gomta/queue"
)

type session struct {
	srv   *Server
	lis   config.Listener
	conn  *smtp.Conn
	tx    *plugin.Tx
	users *auth.Store

	mu           sync.Mutex
	authed       bool
	authUser     string
	authFailures int
	mailSet      bool
	rcpts        map[string]bool
}

func (s *Server) newSession(c *smtp.Conn, lis config.Listener) (smtp.Session, error) {
	sess := &session{
		srv:   s,
		lis:   lis,
		conn:  c,
		users: s.users,
		rcpts: make(map[string]bool),
	}
	sess.resetMessage()
	sess.tx.Helo = c.Hostname()
	sess.tx.Mode = plugin.Mode(lis.Mode)
	sess.tx.ServerName = s.cfg.Hostname
	sess.tx.Arrived = time.Now()
	if addr := c.Conn().RemoteAddr(); addr != nil {
		sess.tx.RemoteAddr = addr.String()
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			host = addr.String()
		}
		sess.tx.RemoteIP = net.ParseIP(strings.Trim(host, "[]"))
		if sess.tx.RemoteIP != nil {
			sess.tx.RemoteIPs = []net.IP{sess.tx.RemoteIP}
		}
	}
	if state, ok := c.TLSConnectionState(); ok {
		sess.tx.TLS = true
		sess.tx.TLSVersion = tlsVersionName(state.Version)
	}

	if res := s.plugins.Run(context.Background(), plugin.HookConnect, sess.tx); res.Rejected() {
		s.logger.Info("connection rejected by plugin", "remote", sess.tx.RemoteAddr, "reason", res.Decision.Message)
		return nil, outcomeError(res.Decision)
	}
	if res := s.plugins.Run(context.Background(), plugin.HookHelo, sess.tx); res.Rejected() {
		s.logger.Info("HELO rejected by plugin", "remote", sess.tx.RemoteAddr, "helo", sess.tx.Helo, "reason", res.Decision.Message)
		return nil, outcomeError(res.Decision)
	}
	s.logger.Debug("SMTP session opened",
		"remote", sess.tx.RemoteAddr,
		"helo", sess.tx.Helo,
		"tls", sess.tx.TLS,
		"mode", lis.Mode,
	)
	return sess, nil
}

func (s *session) resetMessage() {
	var preserved map[string]any
	if s.tx != nil {
		preserved = s.tx.MetaSnapshot()
	}
	tx := plugin.NewTx()
	for k, v := range preserved {
		if strings.HasPrefix(k, "connect.") || strings.HasPrefix(k, "helo.") || strings.HasPrefix(k, "dnsbl.") {
			tx.SetMeta(k, v)
		}
	}
	if s.tx != nil {
		tx.ID = s.tx.ID
		tx.RemoteIP = s.tx.RemoteIP
		tx.RemoteIPs = s.tx.RemoteIPs
		tx.RemoteAddr = s.tx.RemoteAddr
		tx.Helo = s.tx.Helo
		tx.TLS = s.tx.TLS
		tx.TLSVersion = s.tx.TLSVersion
		tx.AuthUser = s.tx.AuthUser
		tx.Mode = s.tx.Mode
		tx.ServerName = s.tx.ServerName
	}
	tx.Arrived = time.Now()
	tx.AuthUser = s.authUser
	s.tx = tx
	s.mailSet = false
	s.rcpts = make(map[string]bool)
}

// AuthMechanisms implements smtp.AuthSession.
func (s *session) AuthMechanisms() []string {
	if s.users == nil || s.users.Len() == 0 {
		return nil
	}
	s.mu.Lock()
	authed := s.authed
	s.mu.Unlock()
	if authed {
		return nil
	}
	if !s.tx.TLS && !s.lis.AllowInsecureAuth {
		return nil
	}
	return []string{sasl.Plain, sasl.Login}
}

// Auth implements smtp.AuthSession.
func (s *session) Auth(mech string) (sasl.Server, error) {
	if s.users == nil || s.users.Len() == 0 {
		return nil, smtp.ErrAuthUnsupported
	}
	if !s.tx.TLS && !s.lis.AllowInsecureAuth {
		return nil, smtp.ErrAuthUnsupported
	}
	s.mu.Lock()
	if s.authFailures >= s.srv.cfg.Limits.MaxAuthFailures {
		s.mu.Unlock()
		return nil, smtp.ErrAuthFailed
	}
	s.mu.Unlock()
	if !s.srv.authGuard.allow(s.tx.RemoteAddr) {
		return nil, smtp.ErrAuthFailed
	}

	verify := func(username, password string) error {
		if !s.srv.authGuard.begin(s.tx.RemoteAddr, s.guardAccountKey(username)) {
			return smtp.ErrAuthFailed
		}
		resolvedUser := s.authenticate(username, password)
		s.srv.authGuard.complete(s.tx.RemoteAddr, s.guardAccountKey(username), resolvedUser != "")
		if resolvedUser == "" {
			s.mu.Lock()
			s.authFailures++
			s.mu.Unlock()
			s.srv.logger.Warn("authentication failed", "remote", s.tx.RemoteAddr, "user", username)
			return smtp.ErrAuthFailed
		}
		s.mu.Lock()
		s.authed = true
		s.authUser = resolvedUser
		s.tx.AuthUser = s.authUser
		s.mu.Unlock()
		s.srv.logger.Info("authentication succeeded", "remote", s.tx.RemoteAddr, "user", s.authUser)
		return nil
	}

	switch strings.ToUpper(strings.TrimSpace(mech)) {
	case sasl.Plain:
		return sasl.NewPlainServer(func(identity, username, password string) error {
			return verify(username, password)
		}), nil
	case sasl.Login:
		return &loginServer{verify: verify}, nil
	default:
		return nil, smtp.ErrAuthUnknownMechanism
	}
}

func (s *session) authenticate(username, password string) string {
	username = strings.ToLower(strings.TrimSpace(username))
	if s.users.Authenticate(username, password) {
		return username
	}
	if strings.Contains(username, "@") {
		return ""
	}
	// Resolve short logins to their actual authenticated mailbox identity.
	for _, domain := range s.srv.domains.List() {
		resolved := username + "@" + domain
		if s.users.Authenticate(resolved, password) {
			return resolved
		}
	}
	return ""
}

type loginServer struct {
	step   int
	user   string
	verify func(string, string) error
}

func (l *loginServer) Next(response []byte) ([]byte, bool, error) {
	switch l.step {
	case 0:
		if len(response) > 0 {
			l.user = string(response)
			l.step = 2
			return []byte("Password:"), false, nil
		}
		l.step = 1
		return []byte("Username:"), false, nil
	case 1:
		l.user = string(response)
		l.step = 2
		return []byte("Password:"), false, nil
	case 2:
		return nil, true, l.verify(l.user, string(response))
	default:
		return nil, true, smtp.ErrAuthFailed
	}
}

func (s *session) Mail(from string, opts *smtp.MailOptions) error {
	s.resetMessage()
	if s.lis.RequireAuth && !s.isAuthed() {
		return smtp.ErrAuthRequired
	}
	from = plugin.NormalizeAddress(from)
	if !plugin.ValidAddress(from, true) {
		return smtpError(501, 5, 1, 7, "Invalid sender address")
	}
	if s.isAuthed() && !s.senderAuthorized(from) {
		return smtpError(553, 5, 7, 1, "Sender is not authorized for this account")
	}
	s.tx.MailFrom = from
	s.mailSet = true
	res := s.srv.plugins.Run(context.Background(), plugin.HookMail, s.tx)
	if res.Rejected() {
		s.srv.logger.Info("message rejected at MAIL", "remote", s.tx.RemoteAddr, "from", from, "reason", res.Decision.Message)
		return outcomeError(res.Decision)
	}
	s.srv.logger.Debug("MAIL accepted", "remote", s.tx.RemoteAddr, "from", from)
	return nil
}

func (s *session) Rcpt(to string, opts *smtp.RcptOptions) error {
	if s.lis.RequireAuth && !s.isAuthed() {
		return smtp.ErrAuthRequired
	}
	if !s.mailSet {
		return smtpError(503, 5, 5, 1, "Need MAIL command first")
	}
	to = plugin.NormalizeAddress(to)
	if !plugin.ValidAddress(to, false) {
		return smtpError(501, 5, 1, 1, "Invalid recipient address")
	}
	domain := plugin.Domain(to)
	if domain == "" {
		return smtpError(501, 5, 1, 1, "Invalid recipient domain")
	}
	if !s.srv.domains.IsLocal(domain) {
		switch plugin.Mode(s.lis.Mode) {
		case plugin.ModeFilter:
			return smtpError(550, 5, 7, 1, "Relaying denied")
		case plugin.ModeSubmission:
			if !s.isAuthed() {
				return smtp.ErrAuthRequired
			}
		default:
			if !s.isAuthed() && !s.srv.isRelayClient(s.tx.RemoteIP) {
				return smtpError(550, 5, 7, 1, "Relaying denied")
			}
		}
	}
	if s.srv.cfg.Limits.ValidateLocalRecipients && s.srv.domains.IsLocal(domain) && (s.users == nil || !s.users.HasUser(to)) {
		return smtpError(550, 5, 1, 1, "Unknown local recipient")
	}
	if s.rcpts[to] {
		return nil
	}
	s.tx.Recipient = to
	res := s.srv.plugins.Run(context.Background(), plugin.HookRcpt, s.tx)
	s.tx.Recipient = ""
	if res.Rejected() {
		s.srv.logger.Info("message rejected at RCPT", "remote", s.tx.RemoteAddr, "from", s.tx.MailFrom, "to", to, "reason", res.Decision.Message)
		return outcomeError(res.Decision)
	}
	s.rcpts[to] = true
	s.tx.RcptTo = append(s.tx.RcptTo, to)
	return nil
}

func (s *session) Data(r io.Reader) error {
	if !s.mailSet || len(s.tx.RcptTo) == 0 {
		return smtpError(503, 5, 5, 1, "Need RCPT command first")
	}
	max := s.lis.MaxMessageBytes
	if max <= 0 {
		max = s.srv.cfg.Limits.MaxMessageBytes
	}
	budgetCtx, budgetCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer budgetCancel()
	if err := s.srv.memory.acquire(budgetCtx, max+1); err != nil {
		return smtpError(452, 4, 3, 1, "Insufficient memory budget for message")
	}
	defer s.srv.memory.release(max + 1)
	s.tx.MaxBodyBytes = max
	s.tx.ID = queue.NewID()
	s.tx.Arrived = time.Now()
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		s.srv.logger.Warn("failed reading message data", "queue_id", s.tx.ID, "error", err)
		return smtpError(451, 4, 3, 0, "Error reading message data")
	}
	if int64(len(data)) > max {
		return smtpError(552, 5, 3, 4, "Message exceeds maximum size")
	}
	s.tx.Data = data
	s.tx.Size = int64(len(data))
	s.tx.Header = parseHeader(data)
	if s.isAuthed() {
		fromValues := s.tx.Header.Values("From")
		if len(fromValues) != 1 {
			return smtpError(553, 5, 7, 1, "Exactly one From header is required")
		}
		addrs, parseErr := mail.ParseAddressList(fromValues[0])
		if parseErr != nil || len(addrs) != 1 || !s.senderAuthorized(addrs[0].Address) {
			return smtpError(553, 5, 7, 1, "From header is not authorized for this account")
		}
	}

	res := s.srv.plugins.Run(context.Background(), plugin.HookData, s.tx)
	if int64(len(s.tx.Data)) > max {
		return smtpError(552, 5, 3, 4, "Message exceeds maximum size after content filtering")
	}
	switch res.Decision.Action {
	case plugin.ActionReject, plugin.ActionTempFail:
		s.srv.logger.Info("message rejected at DATA", "queue_id", s.tx.ID, "remote", s.tx.RemoteAddr, "from", s.tx.MailFrom, "reason", res.Decision.Message)
		return outcomeError(res.Decision)
	case plugin.ActionDiscard:
		s.srv.logger.Info("message discarded by plugin", "queue_id", s.tx.ID, "from", s.tx.MailFrom)
		s.resetMessage()
		return nil
	case plugin.ActionQuarantine:
		return s.quarantineAndAccept(fmt.Sprintf("quarantined at DATA: %s", res.Decision.Message))
	}

	if headers := s.tx.TakeHeaders(); len(headers) > 0 {
		s.tx.Data = plugin.PrependHeaders(s.tx.Data, headers)
		s.tx.Size = int64(len(s.tx.Data))
	}
	s.tx.Data = plugin.PrependHeaders(s.tx.Data, []plugin.Header{receivedHeader(s.tx)})
	s.tx.Size = int64(len(s.tx.Data))
	if s.tx.Size > max {
		return smtpError(552, 5, 3, 4, "Message exceeds maximum size after adding headers")
	}

	res = s.srv.plugins.Run(context.Background(), plugin.HookQueue, s.tx)
	if int64(len(s.tx.Data)) > max {
		return smtpError(552, 5, 3, 4, "Message exceeds maximum size after queue filtering")
	}
	switch res.Decision.Action {
	case plugin.ActionReject, plugin.ActionTempFail:
		s.srv.logger.Info("message rejected at queue", "queue_id", s.tx.ID, "from", s.tx.MailFrom, "reason", res.Decision.Message)
		return outcomeError(res.Decision)
	case plugin.ActionDiscard:
		s.srv.logger.Info("message discarded at queue", "queue_id", s.tx.ID, "from", s.tx.MailFrom)
		s.resetMessage()
		return nil
	case plugin.ActionQuarantine:
		return s.quarantineAndAccept(fmt.Sprintf("quarantined at queue: %s", res.Decision.Message))
	}
	if headers := s.tx.TakeHeaders(); len(headers) > 0 {
		s.tx.Data = plugin.PrependHeaders(s.tx.Data, headers)
		s.tx.Size = int64(len(s.tx.Data))
	}
	if s.tx.Size > max {
		return smtpError(552, 5, 3, 4, "Message exceeds maximum size after queue headers")
	}

	env := s.envelope()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := s.srv.queue.Enqueue(ctx, env, s.tx.Data); err != nil {
		s.srv.logger.Error("queue write failed", "queue_id", env.ID, "error", err)
		return smtpError(451, 4, 3, 0, "Unable to queue message, try again")
	}
	s.srv.logger.Info("message accepted",
		"queue_id", env.ID,
		"remote", s.tx.RemoteAddr,
		"helo", s.tx.Helo,
		"from", env.From,
		"recipients", len(env.Recipients),
		"size", s.tx.Size,
		"tls", s.tx.TLS,
		"auth_user", s.tx.AuthUser,
	)
	s.resetMessage()
	return nil
}

func (s *session) quarantineAndAccept(reason string) error {
	env := s.envelope()
	if err := queue.SaveQuarantine(s.srv.cfg.DataDir, env, s.tx.Data); err != nil {
		s.srv.logger.Error("failed to quarantine message", "queue_id", env.ID, "error", err)
		return smtpError(451, 4, 3, 0, "Unable to quarantine message")
	}
	s.srv.logger.Warn("message quarantined", "queue_id", env.ID, "reason", reason)
	s.resetMessage()
	return nil
}

func (s *session) envelope() *queue.Envelope {
	env := &queue.Envelope{
		ID:          s.tx.ID,
		From:        s.tx.MailFrom,
		Mode:        string(s.tx.Mode),
		Helo:        s.tx.Helo,
		RemoteIP:    "",
		AuthUser:    s.tx.AuthUser,
		ServerName:  s.tx.ServerName,
		Created:     time.Now(),
		NextAttempt: time.Now(),
		Meta:        make(map[string]string),
	}
	if s.tx.RemoteIP != nil {
		env.RemoteIP = s.tx.RemoteIP.String()
	}
	for _, rcpt := range s.tx.RcptTo {
		env.Recipients = append(env.Recipients, queue.Recipient{Address: rcpt, Status: "pending"})
	}
	for k, v := range s.tx.MetaSnapshot() {
		if v == nil {
			continue
		}
		env.Meta[k] = fmt.Sprint(v)
	}
	if s.tx.AuthUser != "" {
		env.Meta["auth_user"] = s.tx.AuthUser
	}
	return env
}

func (s *session) Reset() {
	s.resetMessage()
}

func (s *session) Logout() error {
	res := s.srv.plugins.Run(context.Background(), plugin.HookDisconnect, s.tx)
	if res.Rejected() {
		s.srv.logger.Debug("disconnect hook returned a decision", "action", res.Decision.Action, "message", res.Decision.Message)
	}
	s.srv.logger.Debug("SMTP session closed", "remote", s.tx.RemoteAddr, "helo", s.tx.Helo)
	return nil
}

func (s *session) isAuthed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authed
}

func receivedHeader(tx *plugin.Tx) plugin.Header {
	helo := plugin.SanitizeHeaderValue(tx.Helo)
	if helo == "" {
		helo = "unknown"
	}
	proto := "ESMTP"
	if tx.TLS {
		proto += "S"
	}
	if tx.AuthUser != "" {
		proto += "A"
	}
	remote := "unknown"
	if tx.RemoteIP != nil {
		remote = tx.RemoteIP.String()
	}
	value := fmt.Sprintf("from %s (%s [%s]) by %s (GoMTA) with %s id %s",
		helo, helo, remote, tx.ServerName, proto, tx.ID)
	if len(tx.RcptTo) == 1 {
		value += fmt.Sprintf(" for <%s>", plugin.SanitizeHeaderValue(tx.RcptTo[0]))
	}
	value += "; " + time.Now().Format(time.RFC1123Z)
	return plugin.Header{Name: "Received", Value: value}
}

func parseHeader(data []byte) textproto.MIMEHeader {
	reader := textproto.NewReader(bufio.NewReader(bytes.NewReader(data)))
	h, err := reader.ReadMIMEHeader()
	if err != nil {
		return make(textproto.MIMEHeader)
	}
	return h
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func outcomeError(o plugin.Outcome) error {
	code := o.Code
	if code == 0 {
		if o.Action == plugin.ActionTempFail {
			code = 451
		} else {
			code = 550
		}
	}
	msg := plugin.SanitizeHeaderValue(o.Message)
	if msg == "" {
		if o.Action == plugin.ActionTempFail {
			msg = "Temporary policy failure"
		} else {
			msg = "Message rejected by policy"
		}
	}
	switch {
	case code == 530:
		return smtpError(code, 5, 7, 0, msg)
	case code == 552:
		return smtpError(code, 5, 3, 4, msg)
	case code >= 500:
		return smtpError(code, 5, 7, 1, msg)
	default:
		return smtpError(code, 4, 7, 1, msg)
	}
}

func smtpError(code, c1, c2, c3 int, msg string) error {
	return &smtp.SMTPError{
		Code:         code,
		EnhancedCode: smtp.EnhancedCode{c1, c2, c3},
		Message:      plugin.SanitizeHeaderValue(msg),
	}
}

var _ smtp.AuthSession = (*session)(nil)
var _ smtp.Session = (*session)(nil)

// senderAuthorized checks the authenticated primary identity and explicit,
// per-account delegated aliases. No domain wildcards or implicit delegation.
func (s *session) senderAuthorized(address string) bool {
	if strings.EqualFold(address, s.authUser) {
		return true
	}
	for account, aliases := range s.srv.cfg.AuthorizedSenders {
		if !strings.EqualFold(account, s.authUser) {
			continue
		}
		for _, alias := range aliases {
			if strings.EqualFold(alias, address) {
				return true
			}
		}
	}
	return false
}

// guardAccountKey folds unambiguous short logins into the same account bucket
// used by full-address authentication, without exposing whether it exists.
func (s *session) guardAccountKey(username string) string {
	username = strings.ToLower(strings.TrimSpace(username))
	if strings.Contains(username, "@") || s.users == nil || s.users.HasUser(username) {
		return username
	}
	var matched string
	for _, domain := range s.srv.domains.List() {
		candidate := username + "@" + domain
		if s.users.HasUser(candidate) {
			if matched != "" {
				return username
			} // ambiguous; preserve original
			matched = candidate
		}
	}
	if matched != "" {
		return matched
	}
	return username
}
