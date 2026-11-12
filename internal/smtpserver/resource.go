package smtpserver

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

type failureWindow struct {
	count int
	expires time.Time
}

type authFailureGuard struct {
	mu sync.Mutex
	attempts map[string]failureWindow
	max int
	window time.Duration
}

func newAuthFailureGuard(perSession int) *authFailureGuard {
	max := perSession * 4
	if max < 10 { max = 10 }
	return &authFailureGuard{attempts: make(map[string]failureWindow), max: max, window: 15*time.Minute}
}

func (g *authFailureGuard) key(remote string) string {
	ip, _, err := net.SplitHostPort(remote)
	if err == nil { return ip }
	return remote
}

func (g *authFailureGuard) allow(remote string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	k := g.key(remote)
	w := g.attempts[k]
	if time.Now().After(w.expires) {
		delete(g.attempts, k)
		return true
	}
	return w.count < g.max
}

func (g *authFailureGuard) failure(remote string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	k := g.key(remote)
	now := time.Now()
	w := g.attempts[k]
	if now.After(w.expires) { w = failureWindow{expires: now.Add(g.window)} }
	w.count++
	g.attempts[k] = w
	if len(g.attempts) > 10000 {
		for key, v := range g.attempts {
			if now.After(v.expires) { delete(g.attempts, key) }
		}
	}
}

func (g *authFailureGuard) success(remote string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.attempts, g.key(remote))
}

// memoryBudget atomically reserves DATA byte budgets across all listeners.
type memoryBudget struct {
	mu sync.Mutex
	limit int64
	used int64
	wait chan struct{}
}

func newMemoryBudget(limit int64) *memoryBudget {
	return &memoryBudget{limit: limit, wait: make(chan struct{})}
}

func (m *memoryBudget) acquire(ctx context.Context, n int64) error {
	if n <= 0 || n > m.limit { return errors.New("message exceeds configured memory budget") }
	for {
		m.mu.Lock()
		if m.used+n <= m.limit {
			m.used += n
			m.mu.Unlock()
			return nil
		}
		wait := m.wait
		m.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (m *memoryBudget) release(n int64) {
	m.mu.Lock()
	m.used -= n
	close(m.wait)
	m.wait = make(chan struct{})
	m.mu.Unlock()
}
