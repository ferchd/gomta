// Package queue implements the persistent on-disk spool and retry engine.
package queue

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ferchd/gomta/delivery"
	"github.com/ferchd/gomta/plugin"
)

// Recipient is one envelope recipient and its delivery state.
type Recipient struct {
	Address   string    `json:"address"`
	Status    string    `json:"status"` // pending, delivered, failed
	Attempts  int       `json:"attempts"`
	LastError string    `json:"last_error,omitempty"`
	Updated   time.Time `json:"updated,omitempty"`
}

// Envelope is the persistent SMTP envelope.
type Envelope struct {
	ID          string            `json:"id"`
	From        string            `json:"from"`
	Recipients  []Recipient       `json:"recipients"`
	Mode        string            `json:"mode"`
	Helo        string            `json:"helo,omitempty"`
	RemoteIP    string            `json:"remote_ip,omitempty"`
	AuthUser    string            `json:"auth_user,omitempty"`
	ServerName  string            `json:"server_name,omitempty"`
	Meta        map[string]string `json:"meta,omitempty"`
	Created     time.Time         `json:"created"`
	Updated     time.Time         `json:"updated"`
	NextAttempt time.Time         `json:"next_attempt"`
	Attempts    int               `json:"attempts"`
}

// Pending returns recipients still awaiting delivery.
func (e *Envelope) Pending() []string {
	var out []string
	for _, r := range e.Recipients {
		if r.Status == "pending" || r.Status == "" {
			out = append(out, r.Address)
		}
	}
	return out
}

// Failed returns recipients that permanently failed.
func (e *Envelope) Failed() []Recipient {
	var out []Recipient
	for _, r := range e.Recipients {
		if r.Status == "failed" {
			out = append(out, r)
		}
	}
	return out
}

// Route selects a backend for one recipient.
type Route struct {
	Key     string
	Backend delivery.Backend
}

// Router maps envelope recipients to delivery backends.
type Router interface {
	Route(env *Envelope, rcpt string) (Route, error)
}

// Config configures the queue manager.
type Config struct {
	Dir             string
	Workers         int
	MaxAttempts     int
	MaxAge          time.Duration
	OrphanGrace     time.Duration
	FailedRetention time.Duration
	SendDSN         bool
	DSNInbound      bool
	Plugins         *plugin.Runner
	Retry           []time.Duration
	Logger          *slog.Logger
}

// Manager owns the spool and delivery workers.
type Manager struct {
	cfg    Config
	router Router
	logger *slog.Logger

	wake chan struct{}
	jobs chan *Envelope

	mu       sync.Mutex
	dsnMu    sync.Mutex
	inflight map[string]bool
	wg       sync.WaitGroup
	ready    atomic.Bool
}

// New creates a queue manager. The spool directory is created lazily.
func New(cfg Config, router Router) (*Manager, error) {
	if router == nil {
		return nil, errors.New("queue: router is required")
	}
	if cfg.Dir == "" {
		return nil, errors.New("queue: dir is required")
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 100
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 5 * 24 * time.Hour
	}
	if cfg.OrphanGrace <= 0 {
		cfg.OrphanGrace = 24 * time.Hour
	}
	if len(cfg.Retry) == 0 {
		cfg.Retry = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, 6 * time.Hour}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("queue: create spool: %w", err)
	}
	return &Manager{
		cfg:      cfg,
		router:   router,
		logger:   cfg.Logger,
		wake:     make(chan struct{}, 1),
		jobs:     make(chan *Envelope, cfg.Workers*4),
		inflight: make(map[string]bool),
	}, nil
}

// NewID returns a sortable, filename-safe queue identifier.
func NewID() string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return time.Now().UTC().Format("20060102T150405") + "-" + hex.EncodeToString(buf)
}

// Enqueue writes the payload before publishing its envelope as the visibility marker.
func (m *Manager) Enqueue(ctx context.Context, env *Envelope, msg []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if env == nil {
		return errors.New("queue: nil envelope")
	}
	if env.ID == "" {
		env.ID = NewID()
	}
	if strings.ContainsAny(env.ID, `/\`) || strings.Contains(env.ID, "..") {
		return errors.New("queue: unsafe envelope ID")
	}
	if env.Created.IsZero() {
		env.Created = time.Now()
	}
	env.Updated = time.Now()
	if env.NextAttempt.IsZero() {
		env.NextAttempt = time.Now()
	}
	for i := range env.Recipients {
		if env.Recipients[i].Status == "" {
			env.Recipients[i].Status = "pending"
		}
	}
	jsonPath, msgPath := m.paths(env.ID)
	if err := atomicWrite(msgPath, msg, 0o600); err != nil {
		return fmt.Errorf("queue: write message: %w", err)
	}
	if err := atomicWrite(jsonPath, mustJSON(env), 0o600); err != nil {
		// The orphan .eml is not visible to workers without its envelope.
		return fmt.Errorf("queue: write envelope: %w", err)
	}
	m.logger.Info("message queued", "queue_id", env.ID, "from", env.From, "recipients", len(env.Recipients))
	select {
	case m.wake <- struct{}{}:
	default:
	}
	return nil
}

// Start launches delivery workers and the scan loop. It blocks until ctx is
// canceled, then waits for in-flight deliveries.
func (m *Manager) Start(ctx context.Context) error {
	m.logger.Info("queue started", "dir", m.cfg.Dir, "workers", m.cfg.Workers)
	defer m.ready.Store(false)
	for i := 0; i < m.cfg.Workers; i++ {
		m.wg.Add(1)
		go m.worker(ctx)
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	maintenance := time.NewTicker(time.Hour)
	defer maintenance.Stop()
	healthy := m.scan(ctx)
	m.cleanupSpool(time.Now())
	m.ready.Store(healthy && m.spoolWritable())
	for {
		select {
		case <-ctx.Done():
			m.wg.Wait()
			return nil
		case <-ticker.C:
			m.ready.Store(m.scan(ctx) && m.spoolWritable())
		case <-m.wake:
			m.ready.Store(m.scan(ctx) && m.spoolWritable())
		case <-maintenance.C:
			m.cleanupSpool(time.Now())
		}
	}
}

func (m *Manager) worker(ctx context.Context) {
	defer m.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case env := <-m.jobs:
			func() {
				defer func() {
					m.mu.Lock()
					delete(m.inflight, env.ID)
					m.mu.Unlock()
				}()
				defer func() {
					if rec := recover(); rec != nil {
						m.logger.Error("queue worker panic", "queue_id", env.ID, "panic", rec)
					}
				}()
				m.process(ctx, env)
			}()
		}
	}
}

func (m *Manager) scan(ctx context.Context) bool {
	entries, err := os.ReadDir(m.cfg.Dir)
	if err != nil {
		m.ready.Store(false)
		m.logger.Error("queue scan failed", "error", err)
		return false
	}
	healthy := true
	now := time.Now()
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		m.mu.Lock()
		if m.inflight[id] {
			m.mu.Unlock()
			continue
		}
		m.mu.Unlock()
		raw, err := os.ReadFile(filepath.Join(m.cfg.Dir, entry.Name()))
		if err != nil {
			healthy = false
			m.logger.Error("queue: cannot read visible envelope", "id", id, "error", err)
			continue
		}
		var env Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			healthy = false
			m.logger.Error("queue: corrupt envelope", "id", id, "error", err)
			continue
		}
		if err := m.sendFailureReports(&env); err != nil {
			healthy = false
			m.logger.Error("queue: notify failed recipients", "id", env.ID, "error", err)
		}
		if !env.NextAttempt.IsZero() && env.NextAttempt.After(now) {
			continue
		}
		if len(env.Pending()) == 0 {
			m.finish(&env, nil)
			continue
		}
		m.mu.Lock()
		if m.inflight[id] {
			m.mu.Unlock()
			continue
		}
		m.inflight[id] = true
		m.mu.Unlock()
		select {
		case m.jobs <- &env:
		case <-ctx.Done():
			return false
		default:
			m.mu.Lock()
			delete(m.inflight, id)
			m.mu.Unlock()
		}
	}
	return healthy
}

func (m *Manager) process(ctx context.Context, env *Envelope) {
	jsonPath, msgPath := m.paths(env.ID)
	msg, err := os.ReadFile(msgPath)
	if err != nil {
		m.logger.Error("queue: cannot read message", "id", env.ID, "error", err)
		m.failAll(env, delivery.Temp(err))
		env.NextAttempt = time.Now().Add(m.retryDelay(env.Attempts))
		_ = atomicWrite(jsonPath, mustJSON(env), 0o600)
		return
	}
	if len(env.Pending()) == 0 {
		m.finish(env, msg)
		return
	}
	if !env.Created.IsZero() && time.Since(env.Created) >= m.cfg.MaxAge {
		for _, rcpt := range env.Pending() {
			m.setResult(env, rcpt, delivery.Temp(errors.New("message exceeded maximum queue age")))
		}
		if err := atomicWrite(jsonPath, mustJSON(env), 0o600); err != nil {
			m.logger.Error("queue: persist expired message failed", "id", env.ID, "error", err)
			return
		}
		m.finish(env, msg)
		return
	}

	env.Attempts++
	env.Updated = time.Now()

	type group struct {
		route Route
		rcpts []string
	}
	groups := make(map[string]*group)
	for _, rcpt := range env.Pending() {
		route, err := m.router.Route(env, rcpt)
		if err != nil || route.Backend == nil {
			m.setResult(env, rcpt, delivery.Temp(fmt.Errorf("route recipient: %w", err)))
			continue
		}
		key := route.Key + "|" + route.Backend.Name()
		g := groups[key]
		if g == nil {
			g = &group{route: route}
			groups[key] = g
		}
		g.rcpts = append(g.rcpts, rcpt)
	}

	for _, g := range groups {
		msgObj := &delivery.Message{
			ID:       env.ID,
			From:     env.From,
			To:       g.rcpts,
			Data:     msg,
			Meta:     env.Meta,
			Mode:     env.Mode,
			Helo:     env.Helo,
			RemoteIP: env.RemoteIP,
		}
		results := g.route.Backend.Deliver(ctx, msgObj)
		reported := make(map[string]error, len(g.rcpts))
		for _, rcpt := range g.rcpts {
			err, ok := results[rcpt]
			if !ok {
				err = delivery.Temp(errors.New("delivery backend returned no result"))
			}
			m.setResult(env, rcpt, err)
			reported[rcpt] = err
		}
		// Commit each independently routed group before attempting another:
		// this reduces duplicate delivery after interruption, while the SMTP
		// transport remains fundamentally at-least-once.
		if err := atomicWrite(jsonPath, mustJSON(env), 0o600); err != nil {
			m.logger.Error("queue: persist recipient group outcomes failed", "id", env.ID, "error", err)
			return
		}
		// Observational hooks execute only after all outcomes are durable.
		for _, rcpt := range g.rcpts {
			m.notifyDelivery(ctx, env, rcpt, reported[rcpt], msg)
		}
		if err := m.sendFailureReports(env); err != nil {
			m.logger.Error("queue: DSN publication deferred", "id", env.ID, "error", err)
		}
	}

	pending := env.Pending()
	if len(pending) == 0 {
		// Persist final recipient states before archiving; a failed archive
		// can then be retried without redelivering successful recipients.
		if err := atomicWrite(jsonPath, mustJSON(env), 0o600); err != nil {
			m.logger.Error("queue: persist final outcomes failed", "id", env.ID, "error", err)
			return
		}
		m.finish(env, msg)
		return
	}
	env.NextAttempt = time.Now().Add(m.retryDelay(env.Attempts))
	if err := atomicWrite(jsonPath, mustJSON(env), 0o600); err != nil {
		m.logger.Error("queue: update envelope failed", "id", env.ID, "error", err)
	}
	for _, rcpt := range env.Recipients {
		if rcpt.Status == "pending" && rcpt.Attempts >= m.cfg.MaxAttempts {
			m.logger.Error("delivery retries exhausted", "queue_id", env.ID, "recipient", rcpt.Address, "error", rcpt.LastError)
		}
	}
}

func (m *Manager) setResult(env *Envelope, address string, err error) {
	for i := range env.Recipients {
		r := &env.Recipients[i]
		if r.Address != address {
			continue
		}
		r.Updated = time.Now()
		if err == nil {
			r.Status = "delivered"
			r.LastError = ""
			m.logger.Info("message delivered", "queue_id", env.ID, "recipient", address)
			return
		}
		r.LastError = err.Error()
		if delivery.IsTemporary(err) {
			r.Attempts++
			if r.Attempts >= m.cfg.MaxAttempts || (!env.Created.IsZero() && time.Since(env.Created) >= m.cfg.MaxAge) {
				r.Status = "failed"
				m.logger.Error("delivery failed permanently after retries", "queue_id", env.ID, "recipient", address, "error", err)
			} else {
				r.Status = "pending"
				m.logger.Warn("temporary delivery failure", "queue_id", env.ID, "recipient", address, "attempt", r.Attempts, "error", err)
			}
			return
		}
		r.Status = "failed"
		m.logger.Error("delivery failed permanently", "queue_id", env.ID, "recipient", address, "error", err)
		return
	}
}

func (m *Manager) failAll(env *Envelope, err error) {
	for i := range env.Recipients {
		if env.Recipients[i].Status == "pending" {
			env.Recipients[i].Attempts++
			env.Recipients[i].LastError = err.Error()
			if env.Recipients[i].Attempts >= m.cfg.MaxAttempts || (!env.Created.IsZero() && time.Since(env.Created) >= m.cfg.MaxAge) {
				env.Recipients[i].Status = "failed"
			}
		}
	}
}

func (m *Manager) finish(env *Envelope, msg []byte) {
	if len(env.Pending()) != 0 {
		return
	}
	jsonPath, msgPath := m.paths(env.ID)
	failed := env.Failed()
	if len(failed) > 0 {
		if msg == nil {
			var err error
			msg, err = os.ReadFile(msgPath)
			if err != nil {
				m.logger.Error("queue: missing failed message payload", "id", env.ID, "error", err)
				return
			}
		}
		failedDir := filepath.Join(m.cfg.Dir, "failed")
		if err := os.MkdirAll(failedDir, 0o700); err != nil {
			m.logger.Error("queue: create failed directory", "id", env.ID, "error", err)
			return
		}
		// Publish the archived envelope only after its payload is durable.
		if err := atomicWrite(filepath.Join(failedDir, env.ID+".eml"), msg, 0o600); err != nil {
			m.logger.Error("queue: archive failed payload", "id", env.ID, "error", err)
			return
		}
		archived := *env
		archived.NextAttempt = time.Time{}
		if err := atomicWrite(filepath.Join(failedDir, env.ID+".json"), mustJSON(&archived), 0o600); err != nil {
			m.logger.Error("queue: archive failed envelope", "id", env.ID, "error", err)
			return
		}
		if err := m.sendFailureReports(env); err != nil {
			m.logger.Error("queue: cannot publish delivery status report", "id", env.ID, "error", err)
			return
		}
		m.logger.Warn("message moved to failed queue", "queue_id", env.ID, "failed_recipients", len(failed))
	}
	// Delete the visibility marker first, so an orphaned payload is inert.
	if err := os.Remove(jsonPath); err != nil && !os.IsNotExist(err) {
		m.logger.Error("queue: remove completed envelope", "id", env.ID, "error", err)
		return
	}
	if err := os.Remove(msgPath); err != nil && !os.IsNotExist(err) {
		m.logger.Warn("queue: remove completed payload", "id", env.ID, "error", err)
	}
}

// SaveQuarantine writes a message and envelope to dir/quarantine for later
// inspection.
func SaveQuarantine(dataDir string, env *Envelope, msg []byte) error {
	dir := filepath.Join(dataDir, "quarantine")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if env.ID == "" {
		env.ID = NewID()
	}
	if err := atomicWrite(filepath.Join(dir, env.ID+".eml"), msg, 0o600); err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dir, env.ID+".json"), mustJSON(env), 0o600)
}

// Stats reports queued, failed, and quarantined message counts.
func (m *Manager) Stats() (queued, failed int) {
	count := func(dir string) int {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return 0
		}
		n := 0
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
				n++
			}
		}
		return n
	}
	return count(m.cfg.Dir), count(filepath.Join(m.cfg.Dir, "failed"))
}

func (m *Manager) retryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	idx := attempt - 1
	if idx >= len(m.cfg.Retry) {
		idx = len(m.cfg.Retry) - 1
	}
	return m.cfg.Retry[idx]
}

func (m *Manager) paths(id string) (string, string) {
	return filepath.Join(m.cfg.Dir, id+".json"), filepath.Join(m.cfg.Dir, id+".eml")
}

func mustJSON(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := atomicReplace(tmpName, path); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		d, err := os.Open(dir)
		if err != nil {
			return err
		}
		err = d.Sync()
		_ = d.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// SortRecipients is used by tests and diagnostics.
func SortRecipients(rs []Recipient) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].Address < rs[j].Address })
}

// Ready reports whether the queue worker pool has started.
func (m *Manager) Ready() bool { return m.ready.Load() }

// notifyDelivery runs an observational post-delivery hook. Decisions cannot
// retroactively change outcomes reported by a remote SMTP/LMTP server.
func (m *Manager) notifyDelivery(ctx context.Context, env *Envelope, rcpt string, deliveryErr error, data []byte) {
	if m.cfg.Plugins == nil {
		return
	}
	tx := plugin.NewTx()
	tx.ID = env.ID
	tx.MailFrom = env.From
	tx.Recipient = rcpt
	tx.RcptTo = []string{rcpt}
	tx.AuthUser = env.AuthUser
	tx.Helo = env.Helo
	tx.Mode = plugin.Mode(env.Mode)
	tx.ServerName = env.ServerName
	tx.RemoteIP = net.ParseIP(env.RemoteIP)
	tx.Data = data
	tx.Size = int64(len(data))
	if deliveryErr == nil {
		tx.SetMeta("delivery.result", "success")
	} else {
		tx.SetMeta("delivery.result", "failure")
		tx.SetMeta("delivery.error", deliveryErr.Error())
	}
	if result := m.cfg.Plugins.Run(ctx, plugin.HookDelivery, tx); result.Rejected() {
		m.logger.Warn("post-delivery hook rejected an immutable outcome", "queue_id", env.ID, "recipient", rcpt)
	}
}

// sendFailureReports publishes an independent DSN for each permanently failed
// recipient. Stable IDs and durable markers prevent ordinary duplicate notices.
func (m *Manager) sendFailureReports(env *Envelope) error {
	if !m.cfg.SendDSN || env.From == "" || !plugin.ValidAddress(env.From, false) {
		return nil
	}
	if !m.cfg.DSNInbound && !strings.EqualFold(env.AuthUser, env.From) {
		return nil
	}
	m.dsnMu.Lock()
	defer m.dsnMu.Unlock()
	for _, recipient := range env.Failed() {
		if err := m.sendRecipientFailureReport(env, recipient); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) sendRecipientFailureReport(env *Envelope, failed Recipient) error {
	hash := sha256.Sum256([]byte(strings.ToLower(failed.Address)))
	id := env.ID + "-dsn-" + hex.EncodeToString(hash[:8])
	marker := filepath.Join(m.cfg.Dir, "failed", id+".dsn")
	if _, err := os.Stat(marker); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(marker), 0o700); err != nil {
		return err
	}
	// A restart after queue publication must not overwrite a previously
	// delivered or in-flight DSN. Marker durability is handled separately.
	if _, err := os.Stat(filepath.Join(m.cfg.Dir, id+".json")); err == nil {
		return atomicWrite(marker, []byte("queued\n"), 0o600)
	} else if !os.IsNotExist(err) {
		return err
	}
	host := env.ServerName
	if !plugin.ValidAddress("postmaster@"+host, false) {
		host = "localhost"
	}
	report := &Envelope{
		ID: id, From: "", Mode: string(plugin.ModeMTA), ServerName: host,
		Recipients: []Recipient{{Address: env.From, Status: "pending"}},
	}
	if err := m.Enqueue(context.Background(), report, buildDSNMessage(host, env, []Recipient{failed})); err != nil {
		return err
	}
	return atomicWrite(marker, []byte("queued\n"), 0o600)
}

// spoolWritable probes the same directory where envelope transactions commit.
func (m *Manager) spoolWritable() bool {
	f, err := os.CreateTemp(m.cfg.Dir, ".readiness-*")
	if err != nil {
		return false
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err := f.Write([]byte("durability-check")); err != nil {
		_ = f.Close()
		return false
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return false
	}
	if err := f.Close(); err != nil {
		return false
	}
	if err := os.Remove(name); err != nil {
		return false
	}
	if runtime.GOOS != "windows" {
		d, err := os.Open(m.cfg.Dir)
		if err != nil {
			return false
		}
		err = d.Sync()
		_ = d.Close()
		if err != nil {
			return false
		}
	}
	return true
}

func buildDSNMessage(host string, env *Envelope, failed []Recipient) []byte {
	boundary := "gomta-" + env.ID
	var b strings.Builder
	fmt.Fprintf(&b, "From: Mail Delivery Subsystem <postmaster@%s>\r\n", host)
	fmt.Fprintf(&b, "To: <%s>\r\n", env.From)
	b.WriteString("Subject: Delivery Status Notification (Failure)\r\n")
	b.WriteString("Auto-Submitted: auto-replied\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Content-Type: multipart/report; report-type=delivery-status; boundary=%q\r\n\r\n", boundary)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n", boundary)
	b.WriteString("Your message could not be delivered to the following recipients:\r\n")
	for _, r := range failed {
		fmt.Fprintf(&b, "  %s\r\n", plugin.SanitizeHeaderValue(r.Address))
	}
	fmt.Fprintf(&b, "\r\n--%s\r\nContent-Type: message/delivery-status\r\n\r\n", boundary)
	fmt.Fprintf(&b, "Reporting-MTA: dns; %s\r\n\r\n", host)
	for _, r := range failed {
		fmt.Fprintf(&b, "Final-Recipient: rfc822; %s\r\nAction: failed\r\nStatus: 5.0.0\r\n", plugin.SanitizeHeaderValue(r.Address))
		reason := plugin.SanitizeHeaderValue(r.LastError)
		if len(reason) > 240 {
			reason = reason[:240]
		}
		if reason != "" {
			fmt.Fprintf(&b, "Diagnostic-Code: smtp; %s\r\n", reason)
		}
		b.WriteString("\r\n")
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return []byte(b.String())
}

// cleanupSpool removes only inert, sufficiently old spool files. Completed
// archived messages are never purged unless FailedRetention is explicitly set.
func (m *Manager) cleanupSpool(now time.Time) {
	entries, err := os.ReadDir(m.cfg.Dir)
	if err != nil {
		m.logger.Error("spool cleanup: cannot list queue", "error", err)
		return
	}
	cutoff := now.Add(-m.cfg.OrphanGrace)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".eml") && !strings.HasPrefix(name, ".tmp-") {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		if strings.HasSuffix(name, ".eml") {
			id := strings.TrimSuffix(name, ".eml")
			m.mu.Lock()
			active := m.inflight[id]
			m.mu.Unlock()
			if active {
				continue
			}
			if _, err := os.Stat(filepath.Join(m.cfg.Dir, id+".json")); err == nil {
				continue
			} else if !os.IsNotExist(err) {
				continue
			}
		}
		if err := os.Remove(filepath.Join(m.cfg.Dir, name)); err != nil && !os.IsNotExist(err) {
			m.logger.Warn("spool cleanup: remove orphan failed", "name", name, "error", err)
		}
	}
	if m.cfg.FailedRetention <= 0 {
		return
	}
	failedDir := filepath.Join(m.cfg.Dir, "failed")
	archived, err := os.ReadDir(failedDir)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		m.logger.Warn("spool cleanup: cannot read failed archive", "error", err)
		return
	}
	retentionCutoff := now.Add(-m.cfg.FailedRetention)
	// First expire archive envelopes, then their payloads; never remove an
	// archive payload whose envelope is still present and potentially readable.
	for _, entry := range archived {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.ModTime().After(retentionCutoff) {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		m.mu.Lock()
		active := m.inflight[id]
		m.mu.Unlock()
		if active {
			continue
		}
		if _, err := os.Stat(filepath.Join(m.cfg.Dir, id+".json")); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			continue
		}
		path := filepath.Join(failedDir, entry.Name())
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			m.logger.Warn("spool cleanup: failed archive envelope removal", "name", entry.Name(), "error", err)
		}
	}
	for _, entry := range archived {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".eml") && !strings.HasSuffix(name, ".dsn") {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.ModTime().After(retentionCutoff) {
			continue
		}
		id := strings.TrimSuffix(strings.TrimSuffix(name, ".eml"), ".dsn")
		if strings.HasSuffix(name, ".dsn") {
			// Markers are retained while their originating message is still
			// visible in the queue or archive, preventing repeated DSNs.
			origin := id
			if pos := strings.LastIndex(origin, "-dsn-"); pos >= 0 {
				origin = origin[:pos]
			}
			if _, err := os.Stat(filepath.Join(m.cfg.Dir, origin+".json")); err == nil {
				continue
			} else if !os.IsNotExist(err) {
				continue
			}
			if _, err := os.Stat(filepath.Join(failedDir, origin+".json")); err == nil {
				continue
			} else if !os.IsNotExist(err) {
				continue
			}
		} else {
			if _, err := os.Stat(filepath.Join(failedDir, id+".json")); err == nil {
				continue
			} else if !os.IsNotExist(err) {
				continue
			}
		}
		if err := os.Remove(filepath.Join(failedDir, name)); err != nil && !os.IsNotExist(err) {
			m.logger.Warn("spool cleanup: remove expired archive artifact failed", "name", name, "error", err)
		}
	}
}
