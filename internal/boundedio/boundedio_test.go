package boundedio

import (
	"bytes"
	"errors"
	"testing"
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
