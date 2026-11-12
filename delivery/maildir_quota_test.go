package delivery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMaildirUsageSumsNestedMailbox(t *testing.T) {
	root := t.TempDir()
	box := filepath.Join(root, "mail", "example.test", "alice")
	if err := os.MkdirAll(filepath.Join(box, "new"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(box, "new", "m1"), []byte("123456"), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := maildirUsage(box)
	if err != nil || n != 6 {
		t.Fatalf("quota usage: %d, %v", n, err)
	}
}

func TestMaildirCachedDomainUsage(t *testing.T) {
	root := t.TempDir()
	q := &maildirQuota{mailboxes: make(map[string]int64)}
	box := filepath.Join(root, "alice", "new")
	if err := os.MkdirAll(box, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(box, "m1"), []byte("123456"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := q.reconcile(root); err != nil {
		t.Fatal(err)
	}
	if q.used != 6 || q.mailboxes["alice"] != 6 {
		t.Fatalf("incorrect domain usage: %+v", q)
	}
	if err := os.WriteFile(filepath.Join(box, "m2"), []byte("1234"), 0o600); err != nil {
		t.Fatal(err)
	}
	if q.used != 6 {
		t.Fatal("cache was unexpectedly rescanned")
	}
	if err := q.reconcile(root); err != nil {
		t.Fatal(err)
	}
	if q.used != 10 {
		t.Fatalf("reconciliation did not detect change: %d", q.used)
	}
}

func TestMaildirCanonicalizesCaseInsensitiveMailbox(t *testing.T) {
	b := &maildirBackend{root: t.TempDir(), maxMailboxBytes: 1 << 20, maxDomainBytes: 1 << 22, quotas: make(map[string]*maildirQuota)}
	msg := &Message{ID: "same-mailbox", Data: []byte("From: test@example.test\r\n\r\nHello\r\n")}
	if err := b.deliverOne("Alice@Example.Test", msg); err != nil { t.Fatal(err) }
	if err := b.deliverOne("alice@example.test", msg); err != nil { t.Fatal(err) }
	entries, err := os.ReadDir(filepath.Join(b.root, "example.test"))
	if err != nil { t.Fatal(err) }
	if len(entries) != 1 || entries[0].Name() != "alice" {
		t.Fatalf("expected only canonical alice mailbox, got %+v", entries)
	}
}
