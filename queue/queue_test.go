package queue

import (
    "context"
    "os"
    "path/filepath"
    "testing"

    "github.com/ferchd/gomta/delivery"
)

type testRouter struct{}
func (testRouter) Route(*Envelope, string) (Route, error) { return Route{}, nil }

var _ = delivery.Message{}

func TestEnqueuePublishesCompletePair(t *testing.T) {
    m, err := New(Config{Dir: t.TempDir()}, testRouter{})
    if err != nil { t.Fatal(err) }
    env := &Envelope{ID: "item-1", From: "sender@example.test", Recipients: []Recipient{{Address:"to@example.test"}}}
    msg := []byte("From: sender@example.test\r\n\r\nHello\r\n")
    if err := m.Enqueue(context.Background(), env, msg); err != nil { t.Fatal(err) }
    b, err := os.ReadFile(filepath.Join(m.cfg.Dir, env.ID+".eml"))
    if err != nil || string(b) != string(msg) { t.Fatalf("payload missing or mismatched: %v", err) }
    if _, err := os.Stat(filepath.Join(m.cfg.Dir, env.ID+".json")); err != nil { t.Fatal(err) }
}

func TestFinishPreservesOriginalIfFailedArchiveCannotBeWritten(t *testing.T) {
    m, err := New(Config{Dir: t.TempDir()}, testRouter{})
    if err != nil { t.Fatal(err) }
    env := &Envelope{ID: "item-2", Recipients: []Recipient{{Address:"to@example.test", Status:"failed"}}}
    msg := []byte("message")
    if err := atomicWrite(filepath.Join(m.cfg.Dir, env.ID+".eml"), msg, 0600); err != nil { t.Fatal(err) }
    if err := atomicWrite(filepath.Join(m.cfg.Dir, env.ID+".json"), mustJSON(env), 0600); err != nil { t.Fatal(err) }
    if err := os.WriteFile(filepath.Join(m.cfg.Dir, "failed"), []byte("not a directory"), 0600); err != nil { t.Fatal(err) }
    m.finish(env, msg)
    for _, ext := range []string{".json", ".eml"} {
        if _, err := os.Stat(filepath.Join(m.cfg.Dir, env.ID+ext)); err != nil { t.Fatalf("lost original %s: %v", ext, err) }
    }
}

func TestFinishArchivesFailedRecipientsBeforeSourceRemoval(t *testing.T) {
    m, err := New(Config{Dir: t.TempDir()}, testRouter{})
    if err != nil { t.Fatal(err) }
    env := &Envelope{ID: "item-3", Recipients: []Recipient{{Address:"ok@example.test", Status:"delivered"}, {Address:"bad@example.test", Status:"failed"}}}
    msg := []byte("message")
    if err := atomicWrite(filepath.Join(m.cfg.Dir, env.ID+".eml"), msg, 0600); err != nil { t.Fatal(err) }
    if err := atomicWrite(filepath.Join(m.cfg.Dir, env.ID+".json"), mustJSON(env), 0600); err != nil { t.Fatal(err) }
    m.finish(env, nil)
    for _, ext := range []string{".json", ".eml"} {
        if _, err := os.Stat(filepath.Join(m.cfg.Dir, "failed", env.ID+ext)); err != nil { t.Fatalf("archive missing %s: %v", ext, err) }
        if _, err := os.Stat(filepath.Join(m.cfg.Dir, env.ID+ext)); !os.IsNotExist(err) { t.Fatalf("source remains %s: %v", ext, err) }
    }
}
