package plugin

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

type testPlugin struct {
	name    string
	hooks   []Hook
	ordered bool
	run     func(context.Context, Hook, *Tx) (Outcome, error)
}

func (p *testPlugin) Name() string     { return p.name }
func (p *testPlugin) Hooks() []Hook    { return p.hooks }
func (p *testPlugin) RunOrdered() bool { return p.ordered }
func (p *testPlugin) Run(ctx context.Context, hook Hook, tx *Tx) (Outcome, error) {
	return p.run(ctx, hook, tx)
}

// newTestRunner builds a runner directly so tests do not touch the global
// registry (which would panic under -count=2).
func newTestRunner(t *testing.T, hooks map[Hook][]entry) *Runner {
	t.Helper()
	return &Runner{
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		workers: 8,
		timeout: 5 * time.Second,
		hooks:   hooks,
	}
}

func testEntry(p Plugin, priority, order int) entry {
	return entry{plugin: p, priority: priority, order: order, timeout: 5 * time.Second}
}

func TestRunnerRunsConcurrently(t *testing.T) {
	sleepy := func(delay time.Duration) func(context.Context, Hook, *Tx) (Outcome, error) {
		return func(ctx context.Context, _ Hook, _ *Tx) (Outcome, error) {
			select {
			case <-time.After(delay):
				return OK(), nil
			case <-ctx.Done():
				return OK(), ctx.Err()
			}
		}
	}
	r := newTestRunner(t, map[Hook][]entry{
		HookMail: {
			testEntry(&testPlugin{name: "slow-a", hooks: []Hook{HookMail}, run: sleepy(150 * time.Millisecond)}, 0, 0),
			testEntry(&testPlugin{name: "slow-b", hooks: []Hook{HookMail}, run: sleepy(150 * time.Millisecond)}, 0, 1),
		},
	})
	start := time.Now()
	res := r.Run(context.Background(), HookMail, NewTx())
	elapsed := time.Since(start)
	if res.Decision.Action != ActionContinue {
		t.Fatalf("unexpected decision: %+v", res.Decision)
	}
	if elapsed >= 280*time.Millisecond {
		t.Fatalf("hooks did not run concurrently: %s", elapsed)
	}
}

func TestRunnerOrderedBodyPipeline(t *testing.T) {
	concurrent := &testPlugin{
		name:  "concurrent",
		hooks: []Hook{HookQueue},
		run: func(context.Context, Hook, *Tx) (Outcome, error) {
			return Outcome{Headers: []Header{{Name: "X-Concurrent", Value: "1"}}}, nil
		},
	}
	orderedA := &testPlugin{
		name:    "ordered-a",
		hooks:   []Hook{HookQueue},
		ordered: true,
		run: func(_ context.Context, _ Hook, tx *Tx) (Outcome, error) {
			if !strings.Contains(string(tx.Data), "X-Concurrent: 1") {
				t.Errorf("ordered plugin did not see concurrent header: %q", tx.Data)
			}
			body := PrependHeaders(tx.Data, []Header{{Name: "X-A", Value: "1"}})
			return Outcome{Body: append(body, []byte("\nA")...)}, nil
		},
	}
	orderedB := &testPlugin{
		name:    "ordered-b",
		hooks:   []Hook{HookQueue},
		ordered: true,
		run: func(_ context.Context, _ Hook, tx *Tx) (Outcome, error) {
			if !strings.Contains(string(tx.Data), "X-A: 1") {
				t.Errorf("higher-priority ordered output missing: %q", tx.Data)
			}
			return Outcome{Body: append(tx.Data, []byte("\nB")...)}, nil
		},
	}
	r := newTestRunner(t, map[Hook][]entry{
		HookQueue: {
			testEntry(concurrent, 5, 0),
			testEntry(orderedA, 10, 1),
			testEntry(orderedB, 20, 2),
		},
	})
	tx := NewTx()
	tx.Data = []byte("X-Original: 1\r\n\r\nbody")
	res := r.Run(context.Background(), HookQueue, tx)
	if res.Decision.Action != ActionContinue {
		t.Fatalf("unexpected decision: %+v", res.Decision)
	}
	data := string(tx.Data)
	if !strings.Contains(data, "X-Original: 1") || !strings.HasSuffix(data, "body\nA\nB") {
		t.Fatalf("unexpected body pipeline output:\n%s", data)
	}
	if !strings.Contains(data, "X-Concurrent: 1") || !strings.Contains(data, "X-A: 1") {
		t.Fatalf("added headers missing:\n%s", data)
	}
}

func TestRunnerDecisionPrecedence(t *testing.T) {
	temp := &testPlugin{name: "tempfail", hooks: []Hook{HookData}, run: func(context.Context, Hook, *Tx) (Outcome, error) {
		return TempFail(451, "try later"), nil
	}}
	reject := &testPlugin{name: "reject", hooks: []Hook{HookData}, run: func(context.Context, Hook, *Tx) (Outcome, error) {
		return Reject(550, "no"), nil
	}}
	r := newTestRunner(t, map[Hook][]entry{
		HookData: {testEntry(temp, 0, 0), testEntry(reject, 10, 1)},
	})
	res := r.Run(context.Background(), HookData, NewTx())
	if res.Decision.Action != ActionReject || res.Decision.Code != 550 {
		t.Fatalf("reject should win: %+v", res.Decision)
	}
}

func TestRunnerFailClosed(t *testing.T) {
	broken := &testPlugin{name: "broken", hooks: []Hook{HookData}, run: func(context.Context, Hook, *Tx) (Outcome, error) {
		return OK(), errors.New("backend unavailable")
	}}
	e := testEntry(broken, 0, 0)
	e.failClosed = true
	r := newTestRunner(t, map[Hook][]entry{HookData: {e}})
	res := r.Run(context.Background(), HookData, NewTx())
	if res.Decision.Action != ActionTempFail || res.Decision.Code != 451 {
		t.Fatalf("expected fail-closed tempfail, got %+v", res.Decision)
	}
}

func TestParseHooks(t *testing.T) {
	hooks, err := ParseHooks([]string{"connect", "DATA", "queue"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hooks) != 3 || hooks[1] != HookData {
		t.Fatalf("unexpected hooks: %v", hooks)
	}
	if _, err := ParseHooks([]string{"bogus"}); err == nil {
		t.Fatal("expected error for unknown hook")
	}
}

func TestRunnerPanicRespectsFailClosed(t *testing.T) {
	broken := &testPlugin{name: "panics", hooks: []Hook{HookData}, run: func(context.Context, Hook, *Tx) (Outcome, error) {
		panic("unexpected failure")
	}}
	e := testEntry(broken, 0, 0)
	e.failClosed = true
	r := newTestRunner(t, map[Hook][]entry{HookData: {e}})
	result := r.Run(context.Background(), HookData, NewTx())
	if result.Decision.Action != ActionTempFail {
		t.Fatalf("expected fail-closed temporary failure: %+v", result.Decision)
	}
	if len(result.Outcomes) != 1 || result.Outcomes[0].Name != "panics" || result.Outcomes[0].Err == nil {
		t.Fatalf("panic outcome not preserved: %+v", result.Outcomes)
	}
}

func TestOrderedPluginTimeoutIsBoundedAndIsolated(t *testing.T) {
	finished := make(chan struct{})
	slow := &testPlugin{name: "ordered-timeout", hooks: []Hook{HookQueue}, ordered: true, run: func(_ context.Context, _ Hook, tx *Tx) (Outcome, error) {
		time.Sleep(100 * time.Millisecond)
		tx.SetMeta("late-write", true)
		close(finished)
		return OK(), nil
	}}
	r := newTestRunner(t, map[Hook][]entry{HookQueue: {testEntry(slow, 0, 0)}})
	r.timeout = 15 * time.Millisecond
	tx := NewTx()
	start := time.Now()
	res := r.Run(context.Background(), HookQueue, tx)
	if !res.TimedOut || res.Decision.Action != ActionTempFail {
		t.Fatalf("ordered timeout not enforced: %+v", res)
	}
	if time.Since(start) > 80*time.Millisecond {
		t.Fatal("ordered callback blocked beyond deadline")
	}
	<-finished
	if _, ok := tx.Meta("late-write"); ok {
		t.Fatal("late plugin modified original transaction")
	}
}
