package delivery

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
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
	if err := b.deliverOne("Alice@Example.Test", msg); err != nil {
		t.Fatal(err)
	}
	if err := b.deliverOne("alice@example.test", msg); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(b.root, "example.test"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "alice" {
		t.Fatalf("expected only canonical alice mailbox, got %+v", entries)
	}
}

func TestMaildirConcurrentDeliveriesShareQuota(t *testing.T) {
	root := t.TempDir()
	b := &maildirBackend{root: root, maxMailboxBytes: 1 << 20, maxDomainBytes: 1 << 21, quotas: make(map[string]*maildirQuota)}
	data := []byte("From: test@example.test\r\n\r\ncontent\r\n")
	const count = 30
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			msg := &Message{ID: fmt.Sprintf("parallel-%d", i), Data: data}
			if err := b.deliverOne("alice@example.test", msg); err != nil {
				t.Errorf("delivery: %v", err)
			}
		}(i)
	}
	wg.Wait()
	items, err := os.ReadDir(filepath.Join(root, "example.test", "alice", "new"))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != count {
		t.Fatalf("expected %d files, got %d", count, len(items))
	}
	q := b.quotaFor("example.test")
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.inflight != 0 {
		t.Fatalf("reservations leaked: %d", q.inflight)
	}
}

func TestMaildirRetryDoesNotDuplicateDelivery(t *testing.T) {
	b := &maildirBackend{root: t.TempDir(), maxMailboxBytes: 1 << 20, maxDomainBytes: 1 << 22, quotas: make(map[string]*maildirQuota)}
	msg := &Message{ID: "stable", Data: []byte("From: test@example.test\r\n\r\nHello\r\n")}
	for _, address := range []string{"Alice@Example.Test", "alice@example.test"} {
		if err := b.deliverOne(address, msg); err != nil {
			t.Fatal(err)
		}
	}
	box := filepath.Join(b.root, "example.test", "alice")
	newFiles, err := os.ReadDir(filepath.Join(box, "new"))
	if err != nil {
		t.Fatal(err)
	}
	if len(newFiles) != 1 {
		t.Fatalf("idempotent delivery created %d files", len(newFiles))
	}
	name := newFiles[0].Name()
	if err := os.Rename(filepath.Join(box, "new", name), filepath.Join(box, "cur", name+":2,S")); err != nil {
		t.Fatal(err)
	}
	if err := b.deliverOne("alice@example.test", msg); err != nil {
		t.Fatal(err)
	}
	newFiles, err = os.ReadDir(filepath.Join(box, "new"))
	if err != nil {
		t.Fatal(err)
	}
	if len(newFiles) != 0 {
		t.Fatalf("message was redelivered after move to cur: %d", len(newFiles))
	}
}

func TestFirstAttemptSkipsCurScanAndRetryFindsMaildirFlags(t *testing.T) {
	b := &maildirBackend{root: t.TempDir(), quotas: make(map[string]*maildirQuota)}
	msg := &Message{ID: "intent-persisted", Attempt: 1, Data: []byte("hello")}
	if err := b.deliverOne("Alice@example.test", msg); err != nil {
		t.Fatal(err)
	}
	box := filepath.Join(b.root, "example.test", "alice")
	files, err := os.ReadDir(filepath.Join(box, "new"))
	if err != nil || len(files) != 1 {
		t.Fatalf("new mail unexpected: %v %+v", err, files)
	}
	name := files[0].Name()
	if err := os.Rename(filepath.Join(box, "new", name), filepath.Join(box, "cur", name+":2,S")); err != nil {
		t.Fatal(err)
	}
	msg.Attempt = 2
	if err := b.deliverOne("alice@example.test", msg); err != nil {
		t.Fatal(err)
	}
	files, err = os.ReadDir(filepath.Join(box, "new"))
	if err != nil || len(files) != 0 {
		t.Fatalf("retry duplicated already-read mail: %v %+v", err, files)
	}
}
