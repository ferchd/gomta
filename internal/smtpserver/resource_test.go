package smtpserver

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestMemoryBudgetReservesAndReleases(t *testing.T) {
	b := newMemoryBudget(10)
	if err := b.acquire(context.Background(), 6); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := b.acquire(ctx, 6); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected timeout: %v", err)
	}
	b.release(6)
	if err := b.acquire(context.Background(), 6); err != nil {
		t.Fatal(err)
	}
	b.release(6)
}

func TestAuthFailuresPersistAcrossConnections(t *testing.T) {
	g := newAuthFailureGuard(1)
	for i := 0; i < 10; i++ {
		if !g.allow("127.0.0.1:123") {
			t.Fatalf("rejected too early at %d", i)
		}
		g.failure("127.0.0.1:123")
	}
	if g.allow("127.0.0.1:456") {
		t.Fatal("reconnect bypassed IP budget")
	}
	if !g.allow("127.0.0.2:123") {
		t.Fatal("other IP blocked")
	}
}

func TestAuthGuardReservesConcurrentAttemptsAndBoundsKeys(t *testing.T) {
	g := newAuthFailureGuard(1)
	for i := 0; i < g.max; i++ {
		if !g.begin("127.0.0.1:1000", "alice@example.test") {
			t.Fatalf("unexpected rejection at attempt %d", i)
		}
	}
	if g.begin("127.0.0.1:9999", "alice@example.test") {
		t.Fatal("parallel connections bypassed the in-flight IP budget")
	}
	g2 := newAuthFailureGuard(1)
	g2.capacity = 2
	if !g2.begin("127.0.0.1:1", "first@example.test") { t.Fatal("first attempt failed") }
	if g2.begin("127.0.0.2:2", "second@example.test") { t.Fatal("guard exceeded key capacity") }
	if len(g2.attempts) > g2.capacity { t.Fatal("guard map grew past capacity") }
}

func TestAuthGuardAccountLimitAcrossIPs(t *testing.T) {
	g := newAuthFailureGuard(1)
	for i:=0; i<g.max*2; i++ {
		if !g.begin(fmt.Sprintf("192.0.2.%d:1234", i), "target@example.test") { t.Fatalf("account blocked prematurely at %d",i) }
	}
	if g.begin("203.0.113.1:1234", "target@example.test") { t.Fatal("account limit bypassed with another IP") }
}
