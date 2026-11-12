package delivery

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/ferchd/gomta/plugin"
)

func init() {
	Register("smtp", NewSMTP)
}

// NewSMTP constructs an SMTP delivery backend. With no smarthost it performs
// direct-to-MX delivery, trying MX hosts in preference order.
func NewSMTP(bc plugin.BuildContext, opts plugin.Options) (Backend, error) {
	b := &smtpBackend{
		smarthost: opts.String("smarthost", ""),
		tlsMode:   strings.ToLower(opts.String("tls", "opportunistic")),
		username:  opts.String("username", ""),
		password:  opts.String("password", ""),
		helo:      opts.String("helo", ""),
		timeout:   opts.Duration("timeout", 2*time.Minute),
		insecure:  opts.Bool("insecure_skip_verify", false),
		dialer:    &net.Dialer{Timeout: opts.Duration("connect_timeout", 15*time.Second)},
	}
	if b.helo == "" {
		b.helo, _ = os.Hostname()
		if b.helo == "" {
			b.helo = "localhost"
		}
	}
	switch b.tlsMode {
	case "opportunistic", "required", "none", "implicit":
	default:
		return nil, fmt.Errorf("tls must be opportunistic, required, none or implicit, got %q", b.tlsMode)
	}
	if b.username != "" {
		if b.password == "" {
			return nil, errors.New("username is set but password is empty")
		}
		if b.tlsMode != "required" && b.tlsMode != "implicit" {
			return nil, errors.New("authenticated SMTP relay requires tls: required or implicit")
		}
		if b.insecure {
			return nil, errors.New("authenticated SMTP relay cannot disable TLS certificate verification")
		}
	}
	return b, nil
}

type smtpBackend struct {
	smarthost string
	tlsMode   string
	username  string
	password  string
	helo      string
	timeout   time.Duration
	insecure  bool
	dialer    *net.Dialer
}

func (b *smtpBackend) Name() string { return "smtp" }

func (b *smtpBackend) Deliver(ctx context.Context, m *Message) map[string]error {
	results := make(map[string]error, len(m.To))
	groups := groupByDomain(m.To)
	for domain, rcpts := range groups {
		hosts, err := b.hosts(ctx, domain)
		if err != nil {
			for _, rcpt := range rcpts {
				results[rcpt] = err
			}
			continue
		}
		// A later MX must only receive recipients that have not succeeded or
		// permanently failed at an earlier host.
		remaining := append([]string(nil), rcpts...)
		for _, host := range hosts {
			if len(remaining) == 0 {
				break
			}
			hostResults, retry := b.sendToHost(ctx, host, m, remaining)
			next := make([]string, 0, len(remaining))
			for _, rcpt := range remaining {
				err, ok := hostResults[rcpt]
				if !ok {
					err = Temp(errors.New("MX backend returned no recipient status"))
				}
				results[rcpt] = err
				if IsTemporary(err) {
					next = append(next, rcpt)
				}
			}
			remaining = next
			if !retry || ctx.Err() != nil {
				break
			}
		}

	}
	return results
}

func (b *smtpBackend) hosts(ctx context.Context, domain string) ([]string, error) {
	if b.smarthost != "" {
		return []string{withPort(b.smarthost, 25)}, nil
	}
	if strings.HasPrefix(domain, "[") {
		return []string{strings.Trim(domain, "[]") + ":25"}, nil
	}
	mxs, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return []string{domain + ":25"}, nil
		}
		return nil, Temp(err)
	}
	if len(mxs) == 0 {
		return []string{domain + ":25"}, nil
	}
	if len(mxs) == 1 && mxs[0].Pref == 0 && mxs[0].Host == "." {
		return nil, Perm(fmt.Errorf("domain %s publishes Null MX (does not accept mail)", domain))
	}
	sort.SliceStable(mxs, func(i, j int) bool { return mxs[i].Pref < mxs[j].Pref })
	out := make([]string, 0, len(mxs))
	for _, mx := range mxs {
		host := strings.TrimSuffix(mx.Host, ".")
		if host == "" {
			continue
		}
		out = append(out, withPort(host, 25))
	}
	if len(out) == 0 {
		out = append(out, domain+":25")
	}
	return out, nil
}

func withPort(host string, defaultPort int) string {
	host = strings.TrimSpace(host)
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	if strings.Count(host, ":") > 1 && !strings.HasPrefix(host, "[") {
		return "[" + host + "]:" + strconv.Itoa(defaultPort)
	}
	return net.JoinHostPort(host, strconv.Itoa(defaultPort))
}

// sendToHost returns per-recipient results and whether another host may be
// tried for temporary failures.
func (b *smtpBackend) sendToHost(ctx context.Context, host string, m *Message, rcpts []string) (map[string]error, bool) {
	results := make(map[string]error, len(rcpts))
	fail := func(err error) (map[string]error, bool) {
		e := classify(err)
		for _, rcpt := range rcpts {
			results[rcpt] = e
		}
		return results, IsTemporary(e)
	}

	client, err := b.dial(ctx, host)
	if err != nil {
		return fail(err)
	}
	defer client.Close()
	client.CommandTimeout = b.timeout
	client.SubmissionTimeout = b.timeout

	if err := client.Hello(b.helo); err != nil {
		return fail(err)
	}
	if b.username != "" {
		if !client.SupportsAuth("PLAIN") {
			return fail(Perm(errors.New("remote server does not advertise AUTH PLAIN")))
		}
		if err := client.Auth(sasl.NewPlainClient("", b.username, b.password)); err != nil {
			return fail(err)
		}
	}
	if err := client.Mail(m.From, nil); err != nil {
		return fail(err)
	}

	accepted := make([]string, 0, len(rcpts))
	for _, rcpt := range rcpts {
		if err := client.Rcpt(rcpt, nil); err != nil {
			results[rcpt] = classify(err)
			continue
		}
		accepted = append(accepted, rcpt)
	}
	if len(accepted) == 0 {
		_ = client.Quit()
		retry := false
		for _, e := range results {
			if IsTemporary(e) {
				retry = true
			}
		}
		return results, retry
	}

	w, err := client.Data()
	if err != nil {
		e := classify(err)
		for _, rcpt := range accepted {
			results[rcpt] = e
		}
		return results, IsTemporary(e)
	}
	if _, err := w.Write(m.Data); err != nil {
		_ = w.Close()
		e := Temp(err)
		for _, rcpt := range accepted {
			results[rcpt] = e
		}
		return results, true
	}
	if err := w.Close(); err != nil {
		e := classify(err)
		for _, rcpt := range accepted {
			results[rcpt] = e
		}
		return results, IsTemporary(e)
	}
	for _, rcpt := range accepted {
		results[rcpt] = nil
	}
	_ = client.Quit()
	retry := false
	for _, e := range results {
		if IsTemporary(e) {
			retry = true
		}
	}
	return results, retry
}

func (b *smtpBackend) dial(ctx context.Context, host string) (*smtp.Client, error) {
	tlsCfg := &tls.Config{
		ServerName:         hostnameForTLS(host),
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: b.insecure,
	}
	dialPlain := func() (net.Conn, error) {
		return b.dialer.DialContext(ctx, "tcp", host)
	}
	switch b.tlsMode {
	case "implicit":
		raw, err := dialPlain()
		if err != nil {
			return nil, err
		}
		tconn := tls.Client(raw, tlsCfg)
		if err := tconn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		return smtp.NewClient(tconn), nil
	case "required":
		raw, err := dialPlain()
		if err != nil {
			return nil, err
		}
		c, err := smtp.NewClientStartTLS(raw, tlsCfg)
		if err != nil {
			_ = raw.Close()
			return nil, err
		}
		return c, nil
	case "none":
		raw, err := dialPlain()
		if err != nil {
			return nil, err
		}
		return smtp.NewClient(raw), nil
	default: // opportunistic
		// Probe for STARTTLS on a plain connection, then reconnect using TLS.
		raw, err := dialPlain()
		if err != nil {
			return nil, err
		}
		probe := smtp.NewClient(raw)
		_ = probe.Hello(b.helo)
		hasTLS, _ := probe.Extension("STARTTLS")
		_ = probe.Close()
		if hasTLS {
			raw, err = dialPlain()
			if err != nil {
				return nil, err
			}
			c, err := smtp.NewClientStartTLS(raw, tlsCfg)
			if err != nil {
				_ = raw.Close()
				return nil, err
			}
			return c, nil
		}
		raw, err = dialPlain()
		if err != nil {
			return nil, err
		}
		return smtp.NewClient(raw), nil
	}
}

func hostnameForTLS(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(h, "[]")
}

func classify(err error) error {
	if err == nil {
		return nil
	}
	var se *smtp.SMTPError
	if errors.As(err, &se) {
		return &Error{Code: se.Code, Temporary: se.Code >= 400 && se.Code < 500, Err: err}
	}
	return Temp(err)
}

func groupByDomain(rcpts []string) map[string][]string {
	out := make(map[string][]string)
	for _, rcpt := range rcpts {
		domain := plugin.Domain(rcpt)
		if domain == "" {
			domain = rcpt
		}
		out[domain] = append(out[domain], rcpt)
	}
	return out
}
