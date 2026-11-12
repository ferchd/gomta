package delivery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	return &maildirBackend{root: path, hostname: opts.String("hostname", "")}, nil
}

type maildirBackend struct {
	root     string
	hostname string
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
	local := plugin.LocalPart(rcpt)
	if domain == "" || local == "" {
		return Perm(fmt.Errorf("invalid recipient %q", rcpt))
	}
	box := filepath.Join(b.root, safeComponent(domain), safeComponent(local))
	for _, sub := range []string{"tmp", "new", "cur"} {
		if err := os.MkdirAll(filepath.Join(box, sub), 0o700); err != nil {
			return Temp(fmt.Errorf("create maildir: %w", err))
		}
	}
	host := b.hostname
	if host == "" {
		host, _ = os.Hostname()
	}
	data := plugin.PrependHeaders(m.Data, []plugin.Header{
		{Name: "Delivered-To", Value: rcpt},
		{Name: "X-Original-To", Value: rcpt},
	})
	if len(data) == 0 || data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	name := fmt.Sprintf("%d.%d.%s.%s", time.Now().UnixNano(), os.Getpid(), randomHex(6), safeComponent(host))
	tmp := filepath.Join(box, "tmp", name)
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
