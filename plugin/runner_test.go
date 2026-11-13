package plugin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
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

func TestOrderedPluginIndividualTimeout(t *testing.T) {
	done := make(chan struct{})
	slow := &testPlugin{name: "ordered-slow", hooks: []Hook{HookQueue}, ordered: true, run: func(_ context.Context, _ Hook, tx *Tx) (Outcome, error) {
		time.Sleep(150 * time.Millisecond)
		tx.SetMeta("delayed", true)
		close(done)
		return OK(), nil
	}}
	r := newTestRunner(t, map[Hook][]entry{HookQueue: {testEntry(slow, 0, 0)}})
	r.hooks[HookQueue][0].timeout = 20 * time.Millisecond
	r.timeout = time.Second
	tx := NewTx()
	started := time.Now()
	out := r.Run(context.Background(), HookQueue, tx)
	if !out.TimedOut || out.Decision.Action != ActionTempFail {
		t.Fatalf("timeout did not fail closed: %+v", out)
	}
	if time.Since(started) > 100*time.Millisecond {
		t.Fatal("individual plugin timeout ignored")
	}
	<-done
	if _, ok := tx.Meta("delayed"); ok {
		t.Fatal("late write reached the original transaction")
	}
}

func TestSnapshotMetadataDoesNotShareNestedMap(t *testing.T) {
	src := NewTx()
	src.SetMeta("settings", map[string]any{"nested": map[string]any{"key": "original"}})
	clone := snapshotTx(src)
	value, _ := clone.Meta("settings")
	value.(map[string]any)["nested"].(map[string]any)["key"] = "modified"
	original, _ := src.Meta("settings")
	if original.(map[string]any)["nested"].(map[string]any)["key"] != "original" {
		t.Fatal("plugin snapshot shared mutable metadata")
	}
}

func TestPluginNestedMetadataChangesArePropagated(t *testing.T) {
	plugin := &testPlugin{name: "metadata", hooks: []Hook{HookData}, run: func(_ context.Context, _ Hook, tx *Tx) (Outcome, error) {
		v, ok := tx.Meta("nested")
		if !ok {
			t.Fatal("metadata absent")
		}
		v.(map[string]any)["inside"].(map[string]any)["count"] = 2
		return OK(), nil
	}}
	r := newTestRunner(t, map[Hook][]entry{HookData: {testEntry(plugin, 0, 0)}})
	tx := NewTx()
	tx.SetMeta("nested", map[string]any{"inside": map[string]any{"count": 1}})
	out := r.Run(context.Background(), HookData, tx)
	if out.Decision.Action != ActionContinue {
		t.Fatal(out.Decision)
	}
	value, _ := tx.Meta("nested")
	if value.(map[string]any)["inside"].(map[string]any)["count"] != 2 {
		t.Fatal("in-place nested metadata modification was lost")
	}
}

func TestRunnerRejectsOversizedPluginBodyBeforeApplyingIt(t *testing.T) {
	large := &testPlugin{name: "oversize", hooks: []Hook{HookData}, ordered: true, run: func(_ context.Context, _ Hook, _ *Tx) (Outcome, error) {
		return Outcome{Action: ActionContinue, Body: []byte("123456789")}, nil
	}}
	r := newTestRunner(t, map[Hook][]entry{HookData: {testEntry(large, 0, 0)}})
	tx := NewTx()
	tx.Data = []byte("original")
	tx.MaxBodyBytes = 8
	result := r.Run(context.Background(), HookData, tx)
	if result.Decision.Action != ActionTempFail {
		t.Fatalf("oversized body not rejected: %+v", result)
	}
	if string(tx.Data) != "original" {
		t.Fatalf("oversized body applied: %q", tx.Data)
	}
}

type prepaidBodyPlugin struct {
	budget   *ByteBudget
	limit    int64
	bodySize int
}

func (*prepaidBodyPlugin) Name() string                    { return "prepaid-test" }
func (*prepaidBodyPlugin) Hooks() []Hook                   { return []Hook{HookData} }
func (*prepaidBodyPlugin) RunOrdered() bool                { return true }
func (p *prepaidBodyPlugin) OutputReservationBytes() int64 { return p.limit }
func (p *prepaidBodyPlugin) Run(_ context.Context, _ Hook, tx *Tx) (Outcome, error) {
	p.budget.mu.Lock()
	used := p.budget.used
	p.budget.mu.Unlock()
	expected := int64(len(tx.Data)) + p.limit
	if used < expected {
		return OK(), fmt.Errorf("prepaid only %d of %d", used, expected)
	}
	body := make([]byte, p.bodySize, p.bodySize+8)
	for i := range body {
		body[i] = 'x'
	}
	return Outcome{Action: ActionContinue, Body: body}, nil
}
func TestPrepaidBodyLeasePersistsUntilTransactionCloses(t *testing.T) {
	p := &prepaidBodyPlugin{limit: 48, bodySize: 16}
	r := newTestRunner(t, map[Hook][]entry{HookData: {testEntry(p, 0, 0)}})
	r.budget = NewByteBudget(96)
	p.budget = r.budget
	tx := NewTx()
	tx.Data = make([]byte, 40)
	tx.MaxBodyBytes = 100
	out := r.Run(context.Background(), HookData, tx)
	if out.Rejected() {
		t.Fatalf("unexpected policy failure: %+v", out)
	}
	r.budget.mu.Lock()
	used := r.budget.used
	r.budget.mu.Unlock()
	if used != 24 {
		t.Fatalf("body reservation released too soon: %d", used)
	}
	tx.Close()
	r.budget.mu.Lock()
	used = r.budget.used
	r.budget.mu.Unlock()
	if used != 0 {
		t.Fatalf("body lease not released: %d", used)
	}
}
func TestOversizedPrepaidBodyReleasesReservation(t *testing.T) {
	p := &prepaidBodyPlugin{limit: 48, bodySize: 16}
	r := newTestRunner(t, map[Hook][]entry{HookData: {testEntry(p, 0, 0)}})
	r.budget = NewByteBudget(96)
	p.budget = r.budget
	tx := NewTx()
	tx.Data = make([]byte, 40)
	tx.MaxBodyBytes = 8
	out := r.Run(context.Background(), HookData, tx)
	if !out.Rejected() {
		t.Fatal("oversized output was accepted")
	}
	r.budget.mu.Lock()
	used := r.budget.used
	r.budget.mu.Unlock()
	if used != 0 {
		t.Fatalf("rejected buffer retained reservation: %d", used)
	}
	tx.Close()
}
func TestPrepaidConcurrentFiltersMakeProgressWithoutCircularWait(t *testing.T) {
	p := &prepaidBodyPlugin{limit: 48, bodySize: 16}
	r := newTestRunner(t, map[Hook][]entry{HookData: {testEntry(p, 0, 0)}})
	r.budget = NewByteBudget(96)
	r.timeout = 2 * time.Second
	p.budget = r.budget
	var wg sync.WaitGroup
	errCh := make(chan error, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tx := NewTx()
			tx.Data = make([]byte, 40)
			tx.MaxBodyBytes = 100
			out := r.Run(context.Background(), HookData, tx)
			if out.Rejected() {
				errCh <- fmt.Errorf("prepaid filter rejected: %+v", out)
			}
			tx.Close()
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
	r.budget.mu.Lock()
	defer r.budget.mu.Unlock()
	if r.budget.used != 0 {
		t.Fatalf("budget leak: %d", r.budget.used)
	}
}

func TestBufferAdmissionCannotFailOpen(t *testing.T) {
	p := &prepaidBodyPlugin{limit: 100, bodySize: 8}
	r := newTestRunner(t, map[Hook][]entry{HookData: {testEntry(p, 0, 0)}})
	r.budget = NewByteBudget(96)
	p.budget = r.budget
	tx := NewTx()
	tx.Data = make([]byte, 40)
	out := r.Run(context.Background(), HookData, tx)
	if out.Decision.Action != ActionTempFail {
		t.Fatalf("resource admission failed open: %+v", out)
	}
	tx.Close()
}
func TestPrependingHeadersDoesNotReleaseRetainedOutput(t *testing.T) {
	b := NewByteBudget(128)
	if err := b.Acquire(context.Background(), 32); err != nil {
		t.Fatal(err)
	}
	tx := NewTx()
	tx.SetBody([]byte("Subject: test\r\n\r\nmessage"), &BodyLease{budget: b, size: 32})
	tx.ApplyHeaders([]Header{{Name: "X-Test", Value: "1"}})
	b.mu.Lock()
	used := b.used
	b.mu.Unlock()
	if used != 32 {
		t.Fatalf("headers released output while still in use: %d", used)
	}
	if !strings.HasPrefix(string(tx.Data), "X-Test: 1") {
		t.Fatalf("headers missing: %q", tx.Data)
	}
	tx.Close()
	b.mu.Lock()
	used = b.used
	b.mu.Unlock()
	if used != 0 {
		t.Fatalf("body lease leaked after Close: %d", used)
	}
}
