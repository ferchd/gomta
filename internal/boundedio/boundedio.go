// Package boundedio provides bounded child-process output capture.
package boundedio

import (
	"bytes"
	"errors"
)

var ErrLimitExceeded = errors.New("child process output exceeds configured limit")

// Capture retains at most Max bytes and fails the writer on overflow,
// causing os/exec's output copying to terminate instead of growing unbounded.
type Capture struct {
	Max      int
	buf      bytes.Buffer
	exceeded bool
}

func (c *Capture) Write(p []byte) (int, error) {
	if c.Max <= 0 {
		c.exceeded = true
		return 0, ErrLimitExceeded
	}
	available := c.Max - c.buf.Len()
	if len(p) > available {
		if available > 0 {
			_, _ = c.buf.Write(p[:available])
		}
		c.exceeded = true
		return available, ErrLimitExceeded
	}
	return c.buf.Write(p)
}

func (c *Capture) Bytes() []byte  { return c.buf.Bytes() }
func (c *Capture) Exceeded() bool { return c.exceeded }

// Truncate consumes all child-process stderr while retaining only Max bytes.
type Truncate struct {
	Max int
	buf bytes.Buffer
}

func (t *Truncate) Write(p []byte) (int, error) {
	n := len(p)
	if space := t.Max - t.buf.Len(); space > 0 {
		if space < n {
			_, _ = t.buf.Write(p[:space])
		} else {
			_, _ = t.buf.Write(p)
		}
	}
	return n, nil
}
func (t *Truncate) String() string { return t.buf.String() }
