package smtpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
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
	if !g2.begin("127.0.0.1:1", "first@example.test") {
		t.Fatal("first attempt failed")
	}
	if g2.begin("127.0.0.2:2", "second@example.test") {
		t.Fatal("guard exceeded key capacity")
	}
	if len(g2.attempts) > g2.capacity {
		t.Fatal("guard map grew past capacity")
	}
}

func TestAuthGuardAccountLimitAcrossIPs(t *testing.T) {
	g := newAuthFailureGuard(1)
	for i := 0; i < g.max*2; i++ {
		if !g.begin(fmt.Sprintf("192.0.2.%d:1234", i), "target@example.test") {
			t.Fatalf("account blocked prematurely at %d", i)
		}
	}
	if g.begin("203.0.113.1:1234", "target@example.test") {
		t.Fatal("account limit bypassed with another IP")
	}
}

func TestProgressiveDATAAllowsManySmallMessages(t *testing.T) {
	budget := newMemoryBudget(128 * 1024)
	const sessions = 20
	var wg sync.WaitGroup
	ready := make(chan struct{})
	var active int32
	for i := 0; i < sessions; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data, release, err := budget.readBounded(strings.NewReader("short message"), 25<<20)
			if err != nil {
				t.Errorf("small message rejected: %v", err)
				return
			}
			if string(data) != "short message" {
				t.Errorf("unexpected DATA: %q", data)
			}
			atomic.AddInt32(&active, 1)
			<-ready
			release()
		}()
	}
	// A 25MiB upfront reservation would fail with this 128KiB budget. With
	// progressive reservations the first four sessions can run concurrently.
	time.Sleep(80 * time.Millisecond)
	if atomic.LoadInt32(&active) < 3 {
		close(ready)
		wg.Wait()
		t.Fatalf("small messages did not share memory: %d", active)
	}
	close(ready)
	wg.Wait()
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if budget.used != 0 {
		t.Fatalf("DATA reservations leaked: %d", budget.used)
	}
}
func TestProgressiveDATARejectsOversizeAndReleasesMemory(t *testing.T) {
	budget := newMemoryBudget(256 * 1024)
	_, release, err := budget.readBounded(strings.NewReader(strings.Repeat("X", 1025)), 1024)
	release()
	if !errors.Is(err, errMessageTooLarge) {
		t.Fatalf("expected size violation, got %v", err)
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if budget.used != 0 {
		t.Fatalf("memory leaked after rejection: %d", budget.used)
	}
}
