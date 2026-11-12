package queue

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/ferchd/gomta/delivery"
	"path/filepath"
	"testing"
)

type testRouter struct{}

func (testRouter) Route(*Envelope, string) (Route, error) { return Route{}, nil }

func TestEnqueuePublishesCompletePair(t *testing.T) {
	m, err := New(Config{Dir: t.TempDir()}, testRouter{})
	if err != nil {
		t.Fatal(err)
	}
	env := &Envelope{ID: "item-1", From: "sender@example.test", Recipients: []Recipient{{Address: "to@example.test"}}}
	msg := []byte("From: sender@example.test\r\n\r\nHello\r\n")
	if err := m.Enqueue(context.Background(), env, msg); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(m.cfg.Dir, env.ID+".eml"))
	if err != nil || string(b) != string(msg) {
		t.Fatalf("payload missing or mismatched: %v", err)
	}
	if _, err := os.Stat(filepath.Join(m.cfg.Dir, env.ID+".json")); err != nil {
		t.Fatal(err)
	}
}

func TestFinishPreservesOriginalIfFailedArchiveCannotBeWritten(t *testing.T) {
	m, err := New(Config{Dir: t.TempDir()}, testRouter{})
	if err != nil {
		t.Fatal(err)
	}
	env := &Envelope{ID: "item-2", Recipients: []Recipient{{Address: "to@example.test", Status: "failed"}}}
	msg := []byte("message")
	if err := atomicWrite(filepath.Join(m.cfg.Dir, env.ID+".eml"), msg, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(m.cfg.Dir, env.ID+".json"), mustJSON(env), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.cfg.Dir, "failed"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	m.finish(env, msg)
	for _, ext := range []string{".json", ".eml"} {
		if _, err := os.Stat(filepath.Join(m.cfg.Dir, env.ID+ext)); err != nil {
			t.Fatalf("lost original %s: %v", ext, err)
		}
	}
}

func TestFinishArchivesFailedRecipientsBeforeSourceRemoval(t *testing.T) {
	m, err := New(Config{Dir: t.TempDir()}, testRouter{})
	if err != nil {
		t.Fatal(err)
	}
	env := &Envelope{ID: "item-3", Recipients: []Recipient{
		{Address: "ok@example.test", Status: "delivered"},
		{Address: "bad@example.test", Status: "failed"},
	}}
	msg := []byte("message")
	if err := atomicWrite(filepath.Join(m.cfg.Dir, env.ID+".eml"), msg, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(m.cfg.Dir, env.ID+".json"), mustJSON(env), 0o600); err != nil {
		t.Fatal(err)
	}
	m.finish(env, nil)
	for _, ext := range []string{".json", ".eml"} {
		if _, err := os.Stat(filepath.Join(m.cfg.Dir, "failed", env.ID+ext)); err != nil {
			t.Fatalf("archive missing %s: %v", ext, err)
		}
		if _, err := os.Stat(filepath.Join(m.cfg.Dir, env.ID+ext)); !os.IsNotExist(err) {
			t.Fatalf("source remains %s: %v", ext, err)
		}
	}
}

func TestFailureDSNForAuthenticatedSubmission(t *testing.T) {
	m, err := New(Config{Dir: t.TempDir(), SendDSN: true}, testRouter{})
	if err != nil {
		t.Fatal(err)
	}
	env := &Envelope{ID: "item-dsn", From: "alice@example.test", AuthUser: "alice@example.test", ServerName: "mail.example.test", Mode: "submission", Recipients: []Recipient{
		{Address: "missing@example.test", Status: "failed", LastError: "550 no such mailbox"},
	}}
	payload := []byte("From: alice@example.test\r\n\r\nbody\r\n")
	if err := atomicWrite(filepath.Join(m.cfg.Dir, env.ID+".eml"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(m.cfg.Dir, env.ID+".json"), mustJSON(env), 0o600); err != nil {
		t.Fatal(err)
	}
	m.finish(env, payload)
	dsnID := recipientDSNID(env.ID, "missing@example.test")
	raw, err := os.ReadFile(filepath.Join(m.cfg.Dir, dsnID+".eml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "Content-Type: message/delivery-status") {
		t.Fatalf("DSN is missing structured delivery status: %s", raw)
	}
	if _, err := os.Stat(filepath.Join(m.cfg.Dir, "failed", dsnID+".dsn")); err != nil {
		t.Fatalf("missing DSN publication marker: %v", err)
	}
	// Archived source may be reconsidered without creating a new DSN.
	m.finish(env, payload)
	if _, err := os.Stat(filepath.Join(m.cfg.Dir, dsnID+".json")); err != nil {
		t.Fatal(err)
	}
}

func TestNoBackscatterForUnverifiedInboundMail(t *testing.T) {
	m, err := New(Config{Dir: t.TempDir(), SendDSN: true}, testRouter{})
	if err != nil {
		t.Fatal(err)
	}
	env := &Envelope{ID: "item-inbound", From: "spoofed@external.test", Recipients: []Recipient{
		{Address: "missing@example.test", Status: "failed"},
	}}
	msg := []byte("body")
	if err := atomicWrite(filepath.Join(m.cfg.Dir, env.ID+".eml"), msg, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(m.cfg.Dir, env.ID+".json"), mustJSON(env), 0o600); err != nil {
		t.Fatal(err)
	}
	m.finish(env, msg)
	if _, err := os.Stat(filepath.Join(m.cfg.Dir, env.ID+"-dsn.json")); !os.IsNotExist(err) {
		t.Fatalf("unsolicited DSN created for unauthenticated sender: %v", err)
	}
}

func TestMessageAgeStopsRetries(t *testing.T) {
	m, err := New(Config{Dir: t.TempDir(), MaxAge: 5 * 24 * time.Hour}, testRouter{})
	if err != nil {
		t.Fatal(err)
	}
	env := &Envelope{ID: "age", Created: time.Now().Add(-6 * 24 * time.Hour), Recipients: []Recipient{
		{Address: "missing@example.test", Status: "pending"},
	}}
	m.setResult(env, "missing@example.test", delivery.Temp(errors.New("timeout")))
	if env.Recipients[0].Status != "failed" {
		t.Fatalf("old message was kept pending: %+v", env.Recipients[0])
	}
}

// recipientDSNID follows the deterministic, recipient-specific queue key.
func recipientDSNID(envelopeID, address string) string {
	h := sha256.Sum256([]byte(strings.ToLower(address)))
	return envelopeID + "-dsn-" + hex.EncodeToString(h[:8])
}

func TestFailureDSNWhileOtherRecipientStillPending(t *testing.T) {
	m, err := New(Config{Dir: t.TempDir(), SendDSN: true}, testRouter{})
	if err != nil {
		t.Fatal(err)
	}
	env := &Envelope{ID: "partial-dsn", From: "alice@example.test", AuthUser: "alice@example.test", ServerName: "mail.example.test", Recipients: []Recipient{
		{Address: "failed@example.test", Status: "failed", LastError: "550 no such mailbox"},
		{Address: "pending@example.test", Status: "pending"},
	}}
	if err := m.sendFailureReports(env); err != nil {
		t.Fatal(err)
	}
	id := recipientDSNID(env.ID, "failed@example.test")
	if _, err := os.Stat(filepath.Join(m.cfg.Dir, id+".json")); err != nil {
		t.Fatal(err)
	}
	if err := m.sendFailureReports(env); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(m.cfg.Dir, "failed", id+".dsn")); err != nil {
		t.Fatal(err)
	}
}

func TestSpoolReadinessOnWritableDirectory(t *testing.T) {
	m, err := New(Config{Dir: t.TempDir()}, testRouter{})
	if err != nil {
		t.Fatal(err)
	}
	if !m.spoolWritable() {
		t.Fatal("writable spool reported unavailable")
	}
}

func TestScanRecoversPendingRecipientDSN(t *testing.T) {
	m, err := New(Config{Dir: t.TempDir(), SendDSN: true}, testRouter{})
	if err != nil {
		t.Fatal(err)
	}
	env := &Envelope{ID: "scan-dsn", From: "alice@example.test", AuthUser: "alice@example.test", ServerName: "mail.example.test", NextAttempt: time.Now().Add(time.Hour),
		Recipients: []Recipient{{Address: "failed@example.test", Status: "failed"}, {Address: "later@example.test", Status: "pending"}}}
	if err := atomicWrite(filepath.Join(m.cfg.Dir, env.ID+".json"), mustJSON(env), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(m.cfg.Dir, env.ID+".eml"), []byte("message"), 0o600); err != nil {
		t.Fatal(err)
	}
	m.scan(context.Background())
	id := recipientDSNID(env.ID, "failed@example.test")
	if _, err := os.Stat(filepath.Join(m.cfg.Dir, id+".json")); err != nil {
		t.Fatalf("scan did not recover failed recipient notice: %v", err)
	}
}

 
func TestCleanupSpoolPreservesVisibleAndYoungOrphans(t *testing.T) {
	root := t.TempDir()
	m, err := New(Config{Dir:root, OrphanGrace: 24*time.Hour}, testRouter{})
	if err != nil { t.Fatal(err) }
	now := time.Now()
	write := func(file string, old bool) {
		path := filepath.Join(root,file)
		if err := os.WriteFile(path, []byte("message"), 0o600); err != nil { t.Fatal(err) }
		if old {
			when := now.Add(-48*time.Hour)
			if err := os.Chtimes(path, when, when); err != nil { t.Fatal(err) }
		}
	}
	write("stale.eml", true)
	write("recent.eml", false)
	write("paired.eml", true)
	write("paired.json", true)
	write(".tmp-old", true)
	m.cleanupSpool(now)
	for _, file := range []string{"stale.eml", ".tmp-old"} {
		if _, err := os.Stat(filepath.Join(root,file)); !os.IsNotExist(err) { t.Fatalf("%s not removed: %v",file,err) }
	}
	for _, file := range []string{"recent.eml", "paired.eml", "paired.json"} {
		if _, err := os.Stat(filepath.Join(root,file)); err != nil { t.Fatalf("%s incorrectly removed: %v",file,err) }
	}
}

func TestFailedRetentionPreservesActiveDSNMarker(t *testing.T) {
	root := t.TempDir()
	m, err := New(Config{Dir: root, FailedRetention:24*time.Hour}, testRouter{})
	if err != nil { t.Fatal(err) }
	if err := os.MkdirAll(filepath.Join(root,"failed"),0o700); err != nil { t.Fatal(err) }
	when := time.Now().Add(-48*time.Hour)
	paths := []string{filepath.Join(root,"original.json"),filepath.Join(root,"failed","original-dsn-abcd.dsn")}
	for _,path := range paths {
		if err := os.WriteFile(path,[]byte("x"),0o600); err != nil { t.Fatal(err) }
		if err := os.Chtimes(path,when,when); err != nil { t.Fatal(err) }
	}
	m.cleanupSpool(time.Now())
	if _,err := os.Stat(paths[1]);err!=nil { t.Fatalf("active DSN marker lost: %v",err) }
}
