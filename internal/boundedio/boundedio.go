// Package boundedio provides bounded child-process output capture.
package boundedio

import (
	"bytes"
	"context"
	"errors"
)

var ErrLimitExceeded = errors.New("child process output exceeds configured limit")

// Capture retains at most Max bytes and fails the writer on overflow,
// causing os/exec's output copying to terminate instead of growing unbounded.
type Capture struct {
	Max      int
	Context  context.Context
	Budget   interface { Acquire(context.Context, int64) error; Release(int64) }
	buf      bytes.Buffer
	held     int64
	exceeded bool
}

func (c *Capture) Write(p []byte) (int, error) {
	if c.Max <= 0 {
		c.exceeded = true
		return 0, ErrLimitExceeded
	}
	available := c.Max - c.buf.Len()
	oversize := len(p) > available
	if oversize {
		p = p[:available]
	}
	if c.Budget != nil && len(p) > 0 {
		ctx := c.Context
		if ctx == nil { ctx = context.Background() }
		if err := c.Budget.Acquire(ctx, int64(len(p))); err != nil { return 0, err }
		c.held += int64(len(p))
	}
	n, err := c.buf.Write(p)
	if oversize {
		c.exceeded = true
		return n, ErrLimitExceeded
	}
	return n, err
}

func (c *Capture) Bytes() []byte  { return c.buf.Bytes() }
func (c *Capture) Exceeded() bool { return c.exceeded }

// Truncate consumes all child-process stderr while retaining only Max bytes.
type Truncate struct {
	Max int
	Context context.Context
	Budget interface { Acquire(context.Context, int64) error; Release(int64) }
	buf bytes.Buffer
	held int64
}

func (t *Truncate) Write(p []byte) (int, error) {
	n := len(p)
	if space := t.Max - t.buf.Len(); space > 0 {
		if space > n { space = n }
		if t.Budget != nil {
			ctx := t.Context
			if ctx == nil { ctx = context.Background() }
			if err := t.Budget.Acquire(ctx, int64(space)); err != nil { return 0, err }
			t.held += int64(space)
		}
		_, _ = t.buf.Write(p[:space])
	}
	return n, nil
}
func (t *Truncate) String() string { return t.buf.String() }

// Bytes returns the bounded stderr capture for diagnostics.
func (t *Truncate) Bytes() []byte { return t.buf.Bytes() }


// Close releases retained-output budget reservations after exec.Run returns.
func (c *Capture) Close() {
	if c.Budget != nil && c.held > 0 {
		c.Budget.Release(c.held)
	}
	c.held = 0
}

func (t *Truncate) Close() {
	if t.Budget != nil && t.held > 0 {
		t.Budget.Release(t.held)
	}
	t.held = 0
}
