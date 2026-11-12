package delivery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ferchd/gomta/plugin"
)

func init() {
	Register("maildir", NewMaildir)
}

// NewMaildir constructs a Maildir delivery backend. Messages are stored at
// <path>/<recipient-domain>/<recipient-local>/{tmp,new,cur}.
func NewMaildir(bc plugin.BuildContext, opts plugin.Options) (Backend, error) {
	path := opts.String("path", "")
	if path == "" {
		return nil, fmt.Errorf("path is required")
	}
	path = bc.Path(path)
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, fmt.Errorf("create maildir root: %w", err)
	}
	return &maildirBackend{
		root:            path,
		hostname:        opts.String("hostname", ""),
		maxMailboxBytes: int64(opts.Int("max_mailbox_bytes", 512*1024*1024)),
		maxDomainBytes:  int64(opts.Int("max_domain_bytes", 5*1024*1024*1024)),
		quotas:          make(map[string]*maildirQuota),
	}, nil
}

type maildirBackend struct {
	root            string
	hostname        string
	mu              sync.Mutex // protects quotas, not all deliveries
	quotas          map[string]*maildirQuota
	mailboxLocks    sync.Map // canonical Maildir directory -> *sync.Mutex
	maxMailboxBytes int64
	maxDomainBytes  int64
}

// maildirQuota is scoped to one domain, so different domains can deliver
// concurrently without rescanning the entire tree on every message.
type maildirQuota struct {
	mu        sync.Mutex
	used      int64
	mailboxes map[string]int64
	lastScan  time.Time
	inflight  int
}

func (b *maildirBackend) Name() string { return "maildir" }

func (b *maildirBackend) Deliver(ctx context.Context, m *Message) map[string]error {
	results := make(map[string]error, len(m.To))
	for _, rcpt := range m.To {
		results[rcpt] = b.deliverOne(rcpt, m)
	}
	return results
}

func (b *maildirBackend) deliverOne(rcpt string, m *Message) error {
	domain := plugin.Domain(rcpt)
	// User identities are case-insensitive in the configured users store.
	local := strings.ToLower(plugin.LocalPart(rcpt))
	if domain == "" || local == "" {
		return Perm(fmt.Errorf("invalid recipient %q", rcpt))
	}
	domainPath := filepath.Join(b.root, safeComponent(domain))
	box := filepath.Join(domainPath, safeComponent(local))
	// Serialize only this mailbox: retries and concurrent deliveries of the
	// same queue ID must not create two distinct message files.
	lock, _ := b.mailboxLocks.LoadOrStore(box, &sync.Mutex{})
	mailboxLock := lock.(*sync.Mutex)
	mailboxLock.Lock()
	defer mailboxLock.Unlock()
	name := maildirMessageName(m.ID, domain, local)
	if name != "" {
		present, err := maildirHasMessage(box, name, m.Attempt != 1)
		if err != nil {
			return Temp(fmt.Errorf("check Maildir delivery identity: %w", err))
		}
		if present {
			return nil
		}
	}
	data := plugin.PrependHeaders(m.Data, []plugin.Header{
		{Name: "Delivered-To", Value: rcpt},
		{Name: "X-Original-To", Value: rcpt},
	})
	if len(data) == 0 || data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	size := int64(len(data))
	// Reserve quota under the per-domain mutex; perform expensive file I/O
	// outside it. Concurrent deliveries still see each other's reservations.
	q := b.quotaFor(domain)
	onDisk := false
	if b.maxMailboxBytes > 0 || b.maxDomainBytes > 0 {
		q.mu.Lock()
		if q.inflight == 0 && (q.lastScan.IsZero() || time.Since(q.lastScan) >= 5*time.Minute) {
			if err := q.reconcile(domainPath); err != nil {
				q.mu.Unlock()
				return Temp(fmt.Errorf("inspect Maildir usage: %w", err))
			}
		}
		if q.inflight == 0 && ((b.maxMailboxBytes > 0 && q.mailboxes[safeComponent(local)]+size > b.maxMailboxBytes) ||
			(b.maxDomainBytes > 0 && q.used+size > b.maxDomainBytes)) {
			// External readers may have removed mail since the last scan.
			if err := q.reconcile(domainPath); err != nil {
				q.mu.Unlock()
				return Temp(fmt.Errorf("reconcile Maildir usage: %w", err))
			}
		}
		if b.maxMailboxBytes > 0 && q.mailboxes[safeComponent(local)]+size > b.maxMailboxBytes {
			q.mu.Unlock()
			return Temp(fmt.Errorf("recipient mailbox quota exceeded"))
		}
		if b.maxDomainBytes > 0 && q.used+size > b.maxDomainBytes {
			q.mu.Unlock()
			return Temp(fmt.Errorf("recipient domain quota exceeded"))
		}
		q.inflight++
		q.used += size
		q.mailboxes[safeComponent(local)] += size
		q.mu.Unlock()
		defer func() {
			q.mu.Lock()
			q.inflight--
			if !onDisk {
				q.used -= size
				q.mailboxes[safeComponent(local)] -= size
			}
			q.mu.Unlock()
		}()
	}
	for _, sub := range []string{"tmp", "new", "cur"} {
		if err := os.MkdirAll(filepath.Join(box, sub), 0o700); err != nil {
			return Temp(fmt.Errorf("create maildir: %w", err))
		}
	}
	host := b.hostname
	if host == "" {
		host, _ = os.Hostname()
	}
	if name == "" {
		name = fmt.Sprintf("%d.%d.%s.%s", time.Now().UnixNano(), os.Getpid(), randomHex(6), safeComponent(host))
	}
	// The tmp name is unique, but the published new/ identity is deterministic
	// for a queued message and its canonical local recipient.
	tmp := filepath.Join(box, "tmp", name+"."+randomHex(6))
	dst := filepath.Join(box, "new", name)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return Temp(fmt.Errorf("create maildir file: %w", err))
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return Temp(fmt.Errorf("write maildir file: %w", err))
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return Temp(fmt.Errorf("sync maildir file: %w", err))
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return Temp(fmt.Errorf("close maildir file: %w", err))
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return Temp(fmt.Errorf("rename maildir file: %w", err))
	}
	onDisk = true
	if runtime.GOOS != "windows" {
		if err := syncMaildir(filepath.Dir(dst)); err != nil {
			return Temp(fmt.Errorf("sync maildir directory: %w", err))
		}
	}
	return nil
}

func safeComponent(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "." || s == ".." {
		return "_"
	}
	var b strings.Builder
	changed := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' || r == '+' || r == '=' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('_')
		changed = true
	}
	out := b.String()
	if changed || len(out) > 120 {
		// Stable collision-resistant suffix: the same address always maps to
		// the same mailbox and distinct originals rarely collide.
		hash := sha256.Sum256([]byte(s))
		if len(out) > 100 {
			out = out[:100]
		}
		out += "-" + hex.EncodeToString(hash[:8])
	}
	return out
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

// syncMaildir makes the successfully renamed mailbox entry durable on POSIX.
func syncMaildir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func maildirUsage(root string) (int64, error) {
	var size int64
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if entry.IsDir() || !entry.Type().IsRegular() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		size += info.Size()
		return nil
	})
	if os.IsNotExist(err) {
		return 0, nil
	}
	return size, err
}

// quotaFor takes only a short global lock to retrieve a domain-scoped quota.
func (b *maildirBackend) quotaFor(domain string) *maildirQuota {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.quotas == nil {
		b.quotas = make(map[string]*maildirQuota)
	}
	key := safeComponent(domain)
	q := b.quotas[key]
	if q == nil {
		q = &maildirQuota{mailboxes: make(map[string]int64)}
		b.quotas[key] = q
	}
	return q
}

// reconcile scans a domain once at startup and periodically thereafter.
// All calls occur while the domain's mutex is held.
func (q *maildirQuota) reconcile(domainPath string) error {
	mailboxes := make(map[string]int64)
	var used int64
	err := filepath.WalkDir(domainPath, func(path string, entry os.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if entry.IsDir() || !entry.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(domainPath, path)
		if err != nil {
			return err
		}
		parts := strings.Split(rel, string(filepath.Separator))
		if len(parts) != 3 || (parts[1] != "new" && parts[1] != "cur" && parts[1] != "tmp") {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		used += info.Size()
		mailboxes[parts[0]] += info.Size()
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	q.used = used
	q.mailboxes = mailboxes
	q.lastScan = time.Now()
	return nil
}

// maildirMessageName produces a stable, safe identity for queued messages.
// Empty IDs (ad-hoc direct backend use) preserve one-file-per-call semantics.
func maildirMessageName(id, domain, local string) string {
	if id == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(id + "\x00" + strings.ToLower(domain) + "\x00" + strings.ToLower(local)))
	return "gomta-" + hex.EncodeToString(hash[:])
}

// maildirHasMessage checks both unread new/ and already-read cur/ entries.
// Mail readers conventionally append :2,<flags> when moving a file to cur/.
func maildirHasMessage(box, name string, scanCur bool) (bool, error) {
	// Exact new/ path is O(1), avoiding a full mailbox listing in the common case.
	_, err := os.Stat(filepath.Join(box, "new", name))
	if err == nil {
		return true, nil
	}
	if !os.IsNotExist(err) {
		return false, err
	}
	if !scanCur {
		return false, nil
	}
	// Only a persisted retry needs to search cur/: a mail reader may have
	// already moved the prior delivery there and added Maildir flags.
	entries, err := os.ReadDir(filepath.Join(box, "cur"))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.Name() == name || strings.HasPrefix(entry.Name(), name+":2,") {
			return true, nil
		}
	}
	return false, nil
}
