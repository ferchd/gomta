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
	"io"
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
	ID               string            `json:"id"`
	From             string            `json:"from"`
	Recipients       []Recipient       `json:"recipients"`
	Mode             string            `json:"mode"`
	Helo             string            `json:"helo,omitempty"`
	RemoteIP         string            `json:"remote_ip,omitempty"`
	AuthUser         string            `json:"auth_user,omitempty"`
	SenderAuthorized bool              `json:"sender_authorized,omitempty"`
	ServerName       string            `json:"server_name,omitempty"`
	Meta             map[string]string `json:"meta,omitempty"`
	Created          time.Time         `json:"created"`
	Updated          time.Time         `json:"updated"`
	NextAttempt      time.Time         `json:"next_attempt"`
	Attempts         int               `json:"attempts"`
	PayloadSize      int64             `json:"payload_size,omitempty"`
	PayloadSHA256    string            `json:"payload_sha256,omitempty"`
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
	MaxMessageBytes int64 // safety ceiling for legacy and corrupt on-disk payloads
	Workers         int
	MaxAttempts     int
	MaxAge          time.Duration
	OrphanGrace     time.Duration
	FailedRetention time.Duration
	QuarantineDir   string
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
	nextScan atomic.Int64 // scheduler hint; full reconciliation at least once per minute
}

// New creates a queue manager. The spool directory is created lazily.
func New(cfg Config, router Router) (*Manager, error) {
	if router == nil {
		return nil, errors.New("queue: router is required")
	}
	if cfg.Dir == "" {
		return nil, errors.New("queue: dir is required")
	}
	if cfg.MaxMessageBytes <= 0 {
		cfg.MaxMessageBytes = 25 << 20
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
	// The checksum is part of the durable envelope, not an untrusted caller
	// supplied value. Legacy envelopes without these fields remain readable.
	sum := sha256.Sum256(msg)
	env.PayloadSize = int64(len(msg))
	env.PayloadSHA256 = hex.EncodeToString(sum[:])
	jsonPath, msgPath := m.paths(env.ID)
	// An envelope without its payload may be in recovery. Never reuse the ID
	// and silently attach a new message to an already accepted envelope.
	if _, err := os.Stat(jsonPath); err == nil {
		return fmt.Errorf("queue: envelope ID %q already exists: %w", env.ID, os.ErrExist)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := atomicCreateExclusive(msgPath, msg, 0o600); err != nil {
		return fmt.Errorf("queue: publish new message: %w", err)
	}
	if err := atomicCreateExclusive(jsonPath, mustJSON(env), 0o600); err != nil {
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
	// Only one process may process a spool. In-memory inflight tracking does
	// not coordinate separate GoMTA instances on a shared filesystem.
	release, err := acquireSpoolLock(m.cfg.Dir)
	if err != nil {
		return fmt.Errorf("queue: acquire exclusive spool lock: %w", err)
	}
	defer release()
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
	// Expensive durability probes run periodically, not on every 2-second
	// queue scan. A failed probe keeps readiness false until the next probe.
	probe := time.NewTicker(30 * time.Second)
	defer probe.Stop()
	healthy := m.scan(ctx)
	m.cleanupSpool(time.Now())
	writable := m.spoolWritable()
	m.ready.Store(healthy && writable)
	for {
		select {
		case <-ctx.Done():
			m.wg.Wait()
			return nil
		case <-ticker.C:
			// Full directory walks are expensive with large deferred queues.
			// Still reconcile every minute to detect external spool changes.
			if deadline := m.nextScan.Load(); deadline > 0 && time.Now().UnixNano() < deadline {
				continue
			}
			healthy = m.scan(ctx)
			m.ready.Store(healthy && writable)
		case <-m.wake:
			healthy = m.scan(ctx)
			m.ready.Store(healthy && writable)
		case <-probe.C:
			writable = m.spoolWritable()
			m.ready.Store(healthy && writable)
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
				// Wake the scheduler after a job changes its on-disk state.
				defer func() {
					select {
					case m.wake <- struct{}{}:
					default:
					}
				}()
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
	nextDue := now.Add(time.Minute) // bounded periodic recovery scan
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
			m.logger.Error("queue: corrupt envelope", "id", id, "error", err)
			if qerr := m.quarantineCorruptBytes(id, raw, "invalid envelope JSON: "+err.Error()); qerr != nil {
				healthy = false
				nextDue = now.Add(2 * time.Second)
				m.logger.Error("queue: preserve corrupt envelope failed", "id", id, "error", qerr)
			}
			continue
		}
		// Never use an ID from persistent JSON to select a different file.
		// Validate before DSN publication, routing, archival or deletion.
		if err := validateEnvelope(id, &env); err != nil {
			m.logger.Error("queue: invalid envelope", "id", id, "error", err)
			if qerr := m.quarantineCorruptBytes(id, raw, "invalid envelope: "+err.Error()); qerr != nil {
				healthy = false
				nextDue = now.Add(2 * time.Second)
				m.logger.Error("queue: preserve invalid envelope failed", "id", id, "error", qerr)
			}
			continue
		}
		if err := m.sendFailureReports(&env); err != nil {
			healthy = false
			m.logger.Error("queue: notify failed recipients", "id", env.ID, "error", err)
		}
		// Completed envelopes still require payload-integrity validation before
		// archival. Schedule them through the same worker path.
		if len(env.Pending()) > 0 && !env.NextAttempt.IsZero() && env.NextAttempt.After(now) {
			if env.NextAttempt.Before(nextDue) {
				nextDue = env.NextAttempt
			}
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
			nextDue = now.Add(2 * time.Second) // jobs channel full; retry soon
		}
	}
	m.nextScan.Store(nextDue.UnixNano())
	return healthy
}

func (m *Manager) process(ctx context.Context, env *Envelope) {
	jsonPath, _ := m.paths(env.ID)
	msg, err := m.readVerifiedPayload(env)
	if err != nil {
		m.logger.Error("queue: cannot validate message", "id", env.ID, "error", err)
		if os.IsNotExist(err) || errors.Is(err, errPayloadCorrupt) {
			if qerr := m.quarantineUnrecoverablePayload(env, err.Error(), nil); qerr != nil {
				m.logger.Error("queue: quarantine invalid payload failed", "id", env.ID, "error", qerr)
			}
			return
		}
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
	// Persist attempt intent before any backend side effect. A restart after
	// an accepted but unjournaled delivery must be identifiable as a retry.
	if err := atomicWrite(jsonPath, mustJSON(env), 0o600); err != nil {
		m.logger.Error("queue: persist delivery intent failed", "id", env.ID, "error", err)
		return
	}

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
			Attempt:  env.Attempts,
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
			msg, err = m.readVerifiedPayload(env)
			if err != nil {
				m.logger.Error("queue: cannot validate payload before archival", "id", env.ID, "error", err)
				if os.IsNotExist(err) || errors.Is(err, errPayloadCorrupt) {
					if qerr := m.quarantineUnrecoverablePayload(env, err.Error(), nil); qerr != nil {
						m.logger.Error("queue: quarantine unarchivable payload failed", "id", env.ID, "error", qerr)
					}
				}
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
	if strings.ContainsAny(env.ID, `/\\`) || strings.Contains(env.ID, "..") {
		return errors.New("queue: unsafe quarantine envelope ID")
	}
	if err := atomicCreateExclusive(filepath.Join(dir, env.ID+".eml"), msg, 0o600); err != nil {
		return err
	}
	return atomicCreateExclusive(filepath.Join(dir, env.ID+".json"), mustJSON(env), 0o600)
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
	// Alias senders are authorized during SMTP submission. Older queued
	// messages lacking this bit remain eligible only when From == AuthUser.
	if !m.cfg.DSNInbound && (env.AuthUser == "" || (!env.SenderAuthorized && !strings.EqualFold(env.AuthUser, env.From))) {
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
	// Atomic writes in auxiliary directories also leave .tmp-* files if a
	// process crashes before rename. Only remove old temporary files, never
	// visible records or user quarantines.
	for _, dir := range []string{
		filepath.Join(m.cfg.Dir, "failed"),
		filepath.Join(m.cfg.Dir, "corrupt"),
		m.cfg.QuarantineDir,
	} {
		if dir == "" {
			continue
		}
		m.cleanupTemporaryFiles(dir, cutoff)
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

// quarantineMissingPayload removes an unrecoverable visible envelope only
// after its complete metadata and a diagnostic have been durably preserved.
// A transient permission or I/O error is NOT treated as a missing payload.
func (m *Manager) quarantineMissingPayload(env *Envelope, cause error) error {
	return m.quarantineUnrecoverablePayload(env, "original message payload is missing: "+cause.Error(), nil)
}

// quarantineUnrecoverablePayload preserves any existing bytes before removing
// the visible envelope. Nothing is delivered once integrity is uncertain.
func (m *Manager) quarantineUnrecoverablePayload(env *Envelope, reason string, payload []byte) error {
	badDir := filepath.Join(m.cfg.Dir, "corrupt")
	if err := os.MkdirAll(badDir, 0o700); err != nil {
		return err
	}
	// Retain the original without copying untrusted file sizes into RAM.
	// Linking the inode into corrupt/ is atomic and does not allocate disk
	// space proportional to a potentially oversized corrupted payload.
	if err := m.preserveCorruptPayload(env.ID, badDir, payload); err != nil {
		return err
	}
	for i := range env.Recipients {
		if env.Recipients[i].Status == "pending" || env.Recipients[i].Status == "" {
			env.Recipients[i].Status = "failed"
			env.Recipients[i].LastError = reason
			env.Recipients[i].Updated = time.Now()
		}
	}
	if err := atomicWrite(filepath.Join(badDir, env.ID+".reason"), []byte(reason+"\n"), 0o600); err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(badDir, env.ID+".json"), mustJSON(env), 0o600); err != nil {
		return err
	}
	if err := m.sendFailureReports(env); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(m.cfg.Dir, env.ID+".json")); err != nil && !os.IsNotExist(err) {
		return err
	}
	m.logger.Error("queue: quarantined unrecoverable message", "id", env.ID, "diagnostic", reason)
	return nil
}

// quarantineCorruptBytes retains malformed envelope bytes for manual repair.
// This path cannot safely infer sender identity or generate a DSN.
func (m *Manager) quarantineCorruptBytes(id string, raw []byte, reason string) error {
	badDir := filepath.Join(m.cfg.Dir, "corrupt")
	if err := os.MkdirAll(badDir, 0o700); err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(badDir, id+".reason"), []byte(reason+"\n"), 0o600); err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(badDir, id+".envelope"), raw, 0o600); err != nil {
		return err
	}
	// A malformed envelope may still refer to an intact payload. Preserve
	// that content before removing the visibility marker: the orphan cleaner
	// would otherwise discard the original .eml after its grace interval.
	if err := m.preserveCorruptPayload(id, badDir, nil); err != nil {
		return err
	}
	return os.Remove(filepath.Join(m.cfg.Dir, id+".json"))
}

func (m *Manager) cleanupTemporaryFiles(dir string, cutoff time.Time) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		m.logger.Warn("spool cleanup: cannot inspect temporary directory", "dir", dir, "error", err)
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), ".tmp-") {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !os.IsNotExist(err) {
			m.logger.Warn("spool cleanup: cannot remove abandoned temp", "dir", dir, "name", entry.Name(), "error", err)
		}
	}
}

// validateEnvelope ensures that a parsed on-disk envelope cannot redirect
// operations to another file (or outside the spool). It runs before *any*
// side effects from a recovered record.
func validateEnvelope(filenameID string, env *Envelope) error {
	if filenameID == "" || strings.ContainsAny(filenameID, "/\\") || strings.Contains(filenameID, "..") {
		return errors.New("invalid spool filename ID")
	}
	if env.ID != filenameID {
		return fmt.Errorf("embedded ID %q does not match spool entry %q", env.ID, filenameID)
	}
	if len(env.Recipients) == 0 {
		return errors.New("envelope contains no recipients")
	}
	if !plugin.ValidAddress(env.From, true) {
		return errors.New("invalid envelope sender")
	}
	if env.Attempts < 0 || env.PayloadSize < 0 {
		return errors.New("negative envelope counter or payload size")
	}
	if env.PayloadSHA256 != "" {
		digest, err := hex.DecodeString(env.PayloadSHA256)
		if err != nil || len(digest) != sha256.Size {
			return errors.New("invalid payload SHA-256")
		}
	}
	seen := make(map[string]bool, len(env.Recipients))
	for _, recipient := range env.Recipients {
		if !plugin.ValidAddress(recipient.Address, false) || recipient.Attempts < 0 {
			return errors.New("invalid recipient or attempt counter")
		}
		if seen[recipient.Address] {
			return fmt.Errorf("duplicate recipient %q", recipient.Address)
		}
		seen[recipient.Address] = true
		switch recipient.Status {
		case "", "pending", "delivered", "failed":
		default:
			return fmt.Errorf("unknown recipient state %q", recipient.Status)
		}
	}
	return nil
}

// errPayloadCorrupt distinguishes content integrity failures from transient
// filesystem errors and stops delivery before any external side effects.
var errPayloadCorrupt = errors.New("queue: payload integrity violation")

// readVerifiedPayload never reads an oversized on-disk file into memory.
// Even a historic envelope without a checksum is bounded by MaxMessageBytes.
// For modern envelopes, stream the digest before materializing the payload.
func (m *Manager) readVerifiedPayload(env *Envelope) ([]byte, error) {
	_, path := m.paths(env.ID)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: not a regular file", errPayloadCorrupt)
	}
	if info.Size() > m.cfg.MaxMessageBytes {
		return nil, fmt.Errorf("%w: payload size %d exceeds %d", errPayloadCorrupt, info.Size(), m.cfg.MaxMessageBytes)
	}
	if env.PayloadSHA256 != "" {
		if info.Size() != env.PayloadSize {
			return nil, fmt.Errorf("%w: committed size %d differs from file size %d", errPayloadCorrupt, env.PayloadSize, info.Size())
		}
		hash := sha256.New()
		n, err := io.Copy(hash, io.LimitReader(f, m.cfg.MaxMessageBytes+1))
		if err != nil {
			return nil, err
		}
		if n != env.PayloadSize || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), env.PayloadSHA256) {
			return nil, fmt.Errorf("%w: payload SHA-256 mismatch", errPayloadCorrupt)
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
	}
	msg, err := io.ReadAll(io.LimitReader(f, m.cfg.MaxMessageBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(msg)) > m.cfg.MaxMessageBytes {
		return nil, fmt.Errorf("%w: payload grew during read", errPayloadCorrupt)
	}
	if env.PayloadSHA256 != "" {
		sum := sha256.Sum256(msg)
		if int64(len(msg)) != env.PayloadSize || !strings.EqualFold(hex.EncodeToString(sum[:]), env.PayloadSHA256) {
			return nil, fmt.Errorf("%w: payload changed during read", errPayloadCorrupt)
		}
	}
	return msg, nil
}

// preserveCorruptPayload retains the same immutable content under corrupt/.
// An existing destination must be the same file; never overwrite evidence.
func (m *Manager) preserveCorruptPayload(id, badDir string, fallback []byte) error {
	src := filepath.Join(m.cfg.Dir, id+".eml")
	dst := filepath.Join(badDir, id+".eml")
	if err := os.Link(src, dst); err != nil {
		if os.IsNotExist(err) {
			if fallback == nil {
				return nil
			}
			return atomicCreateExclusive(dst, fallback, 0o600)
		}
		if !os.IsExist(err) {
			return fmt.Errorf("preserve corrupt payload: %w", err)
		}
		a, aErr := os.Stat(src)
		b, bErr := os.Stat(dst)
		if aErr != nil || bErr != nil || !os.SameFile(a, b) {
			return fmt.Errorf("corrupt payload already exists for different message: %w", os.ErrExist)
		}
	}
	return syncQueueDirectory(badDir)
}

// atomicCreateExclusive publishes new spool files without ever replacing an
// existing ID. A unique fsynced temporary file is linked atomically into
// the namespace, then its directory is synced on POSIX. Existing envelopes
// still use atomicWrite for their validated state transitions.
func atomicCreateExclusive(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
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
	if err := os.Link(tmp.Name(), path); err != nil {
		return err
	}
	return syncQueueDirectory(dir)
}

func syncQueueDirectory(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// CorruptStats reports the number of persisted corruption diagnostics and
// the age of the oldest. Counting .reason includes incomplete quarantines
// whose envelope has not yet been safely removed.
func (m *Manager) CorruptStats() (count int, oldestAge time.Duration) {
	entries, err := os.ReadDir(filepath.Join(m.cfg.Dir, "corrupt"))
	if err != nil {
		return 0, 0
	}
	var oldest time.Time
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".reason") {
			continue
		}
		count++
		info, err := entry.Info()
		if err == nil && (oldest.IsZero() || info.ModTime().Before(oldest)) {
			oldest = info.ModTime()
		}
	}
	if !oldest.IsZero() {
		oldestAge = time.Since(oldest)
	}
	return
}
