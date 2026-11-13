package boundedio

import (
	"bytes"
	"context"
	"errors"
	"github.com/ferchd/gomta/plugin"
	"testing"
	"time"
)

func TestCaptureStopsAtLimit(t *testing.T) {
	w := &Capture{Max: 8}
	n, err := w.Write([]byte("1234567890123"))
	if n != 8 || !errors.Is(err, ErrLimitExceeded) || !w.Exceeded() {
		t.Fatalf("overflow returned n=%d err=%v exceeded=%v", n, err, w.Exceeded())
	}
	if len(w.Bytes()) != 8 {
		t.Fatalf("captured %d bytes", len(w.Bytes()))
	}
}
func TestTruncateNeverAccumulatesPastLimit(t *testing.T) {
	w := &Truncate{Max: 16}
	for i := 0; i < 50; i++ {
		if n, err := w.Write(bytes.Repeat([]byte("x"), 100)); n != 100 || err != nil {
			t.Fatalf("write n=%d err=%v", n, err)
		}
	}
	if len(w.String()) != 16 {
		t.Fatal("stderr was not capped")
	}
}

func TestConcurrentCapturesShareBudget(t *testing.T) {
	budget := plugin.NewByteBudget(10)
	first := &Capture{Max: 10, Budget: budget}
	if _, err := first.Write([]byte("12345678")); err != nil {
		t.Fatal(err)
	}
	second := &Capture{Max: 10, Budget: budget}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	second.Context = ctx
	if _, err := second.Write([]byte("12345")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("aggregate budget not enforced: %v", err)
	}
	first.Close()
	second.Context = context.Background()
	if _, err := second.Write([]byte("12345")); err != nil {
		t.Fatal(err)
	}
	second.Close()
}

func TestCaptureNeverAllocatesBeyondMaximumCapacity(t *testing.T) {
	c := &Capture{Max: 10}
	for _, data := range []string{"123", "456", "7890"} {
		if _, err := c.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
		if cap(c.Bytes()) > c.Max {
			t.Fatalf("capacity %d exceeds Max %d", cap(c.Bytes()), c.Max)
		}
	}
	if string(c.Bytes()) != "1234567890" {
		t.Fatalf("unexpected output %q", c.Bytes())
	}
	if _, err := c.Write([]byte("x")); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("limit not enforced: %v", err)
	}
}
