package smtpserver

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

type failureWindow struct {
	count   int
	expires time.Time
}

// authFailureGuard counts both failed and in-flight authentication attempts
// atomically, across SMTP sessions. Keys are bounded to avoid growing without
// limit when exposed to a high-cardinality source of usernames or addresses.
type authFailureGuard struct {
	mu       sync.Mutex
	attempts map[string]failureWindow
	max      int
	window   time.Duration
	capacity int
}

func newAuthFailureGuard(perSession int) *authFailureGuard {
	max := perSession * 4
	if max < 10 {
		max = 10
	}
	return &authFailureGuard{attempts: make(map[string]failureWindow), max: max, window: 15 * time.Minute, capacity: 10000}
}

func (g *authFailureGuard) key(remote string) string {
	ip, _, err := net.SplitHostPort(remote)
	if err == nil {
		return ip
	}
	return remote
}

func (g *authFailureGuard) activeLocked(key string, now time.Time) failureWindow {
	w := g.attempts[key]
	if now.After(w.expires) {
		delete(g.attempts, key)
		return failureWindow{}
	}
	return w
}

func (g *authFailureGuard) capacityForLocked(keys []string, now time.Time) bool {
	missing := 0
	for _, key := range keys {
		if _, ok := g.attempts[key]; !ok {
			missing++
		}
	}
	if len(g.attempts)+missing <= g.capacity {
		return true
	}
	for key, value := range g.attempts {
		if now.After(value.expires) {
			delete(g.attempts, key)
		}
	}
	return len(g.attempts)+missing <= g.capacity
}

// begin reserves both an IP and username slot before verifying a password.
func (g *authFailureGuard) begin(remote, username string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	keys := []string{"ip:" + g.key(remote), "account:" + strings.ToLower(strings.TrimSpace(username))}
	limits := []int{g.max, g.max * 2}
	for i, key := range keys {
		if g.activeLocked(key, now).count >= limits[i] {
			return false
		}
	}
	if !g.capacityForLocked(keys, now) {
		return false
	}
	for _, key := range keys {
		w := g.activeLocked(key, now)
		if w.expires.IsZero() {
			w.expires = now.Add(g.window)
		}
		w.count++
		g.attempts[key] = w
	}
	return true
}

// complete removes successful attempts from both budgets. Failed attempts
// remain until the fixed window expires.
func (g *authFailureGuard) complete(remote, username string, success bool) {
	if !success {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, key := range []string{"ip:" + g.key(remote), "account:" + strings.ToLower(strings.TrimSpace(username))} {
		w, ok := g.attempts[key]
		if !ok {
			continue
		}
		if w.count > 0 {
			w.count--
		}
		if w.count == 0 {
			delete(g.attempts, key)
		} else {
			g.attempts[key] = w
		}
	}
}

// allow/failure retain compatibility with standalone guard tests.
func (g *authFailureGuard) allow(remote string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.activeLocked("ip:"+g.key(remote), time.Now()).count < g.max
}

func (g *authFailureGuard) failure(remote string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	k := "ip:" + g.key(remote)
	w := g.activeLocked(k, time.Now())
	if w.expires.IsZero() {
		w.expires = time.Now().Add(g.window)
	}
	w.count++
	g.attempts[k] = w
}

func (g *authFailureGuard) success(remote string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.attempts, "ip:"+g.key(remote))
}

// memoryBudget atomically reserves DATA byte budgets across all listeners.
type memoryBudget struct {
	mu    sync.Mutex
	limit int64
	used  int64
	wait  chan struct{}
}

func newMemoryBudget(limit int64) *memoryBudget {
	return &memoryBudget{limit: limit, wait: make(chan struct{})}
}

func (m *memoryBudget) acquire(ctx context.Context, n int64) error {
	if n <= 0 || n > m.limit {
		return errors.New("message exceeds configured memory budget")
	}
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

// errMessageTooLarge distinguishes SMTP message-size violations from resource
// exhaustion so callers can return an appropriate permanent SMTP response.
var errMessageTooLarge = errors.New("message exceeds maximum SMTP DATA size")

// readBounded reserves capacity progressively instead of booking the entire
// configured message maximum for every small SMTP transaction. Reservations
// track retained slice capacity (not the Go runtime's temporary GC overhead).
// The caller must invoke release exactly once after it stops using the bytes.
func (m *memoryBudget) readBounded(r io.Reader, max int64) (data []byte, release func(), err error) {
	var held int64
	var once sync.Once
	release = func() {
		once.Do(func() {
			if held > 0 {
				m.release(held)
			}
		})
	}
	if max < 1 {
		return nil, release, errMessageTooLarge
	}
	limited := io.LimitReader(r, max+1)
	buf := make([]byte, 32*1024)
	noProgress := 0
	for {
		n, readErr := limited.Read(buf)
		if n > 0 {
			noProgress = 0
			want := int64(len(data)) + int64(n)
			if want > max {
				release()
				return nil, func() {}, errMessageTooLarge
			}
			if want > int64(cap(data)) {
				newCapacity := int64(cap(data)) * 2
				if newCapacity < 32*1024 {
					newCapacity = 32 * 1024
				}
				if newCapacity < want {
					newCapacity = want
				}
				if newCapacity > max {
					newCapacity = max
				}
				// Both slices coexist while copying; charge the new capacity
				// before allocation and release the old charge afterwards.
				budgetCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				reserveErr := m.acquire(budgetCtx, newCapacity)
				cancel()
				if reserveErr != nil {
					release()
					return nil, func() {}, reserveErr
				}
				oldSize := held
				next := make([]byte, len(data), int(newCapacity))
				copy(next, data)
				data = next
				held = newCapacity
				if oldSize > 0 {
					m.release(oldSize)
				}
			}
			data = append(data, buf[:n]...)
		} else if readErr == nil {
			noProgress++
			if noProgress > 100 {
				release()
				return nil, func() {}, io.ErrNoProgress
			}
		}
		if readErr == io.EOF {
			return data, release, nil
		}
		if readErr != nil {
			release()
			return nil, func() {}, readErr
		}
	}
}
