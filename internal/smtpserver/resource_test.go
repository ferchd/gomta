package smtpserver

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryBudgetReservesAndReleases(t *testing.T) {
	b := newMemoryBudget(10)
	if err := b.acquire(context.Background(), 6); err != nil { t.Fatal(err) }
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := b.acquire(ctx, 6); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected timeout: %v", err)
	}
	b.release(6)
	if err := b.acquire(context.Background(), 6); err != nil { t.Fatal(err) }
	b.release(6)
}

func TestAuthFailuresPersistAcrossConnections(t *testing.T) {
	g := newAuthFailureGuard(1)
	for i := 0; i < 10; i++ {
		if !g.allow("127.0.0.1:123") { t.Fatalf("rejected too early at %d", i) }
		g.failure("127.0.0.1:123")
	}
	if g.allow("127.0.0.1:456") { t.Fatal("reconnect bypassed IP budget") }
	if !g.allow("127.0.0.2:123") { t.Fatal("other IP blocked") }
}
