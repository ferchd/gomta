package plugin

import (
	"context"
	"errors"
	"sync"
)

var ErrBudgetExceeded = errors.New("plugin memory request exceeds configured budget")

// ByteBudget coordinates retained DATA snapshots and subprocess output
// across all plugins created by one Runner. It is not an RSS hard limit.
type ByteBudget struct {
	mu sync.Mutex
	limit int64
	used int64
	wake chan struct{}
}

func NewByteBudget(limit int64) *ByteBudget {
	return &ByteBudget{limit: limit, wake: make(chan struct{})}
}

func (b *ByteBudget) Acquire(ctx context.Context, size int64) error {
	if size <= 0 || b == nil || b.limit <= 0 { return nil }
	if size > b.limit { return ErrBudgetExceeded }
	for {
		b.mu.Lock()
		if b.used+size <= b.limit {
			b.used += size
			b.mu.Unlock()
			return nil
		}
		wake := b.wake
		b.mu.Unlock()
		select {
		case <-wake:
		case <-ctx.Done(): return ctx.Err()
		}
	}
}

func (b *ByteBudget) Release(size int64) {
	if size <= 0 || b == nil || b.limit <= 0 { return }
	b.mu.Lock()
	b.used -= size
	close(b.wake)
	b.wake = make(chan struct{})
	b.mu.Unlock()
}
