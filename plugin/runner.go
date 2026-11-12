package plugin

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"
)

// Definition is the YAML representation of one configured plugin.
type Definition struct {
	Name       string   `yaml:"name"`
	Enabled    *bool    `yaml:"enabled"`
	Priority   int      `yaml:"priority"`
	Timeout    string   `yaml:"timeout"`
	FailClosed *bool    `yaml:"fail_closed"`
	Hooks      []string `yaml:"hooks"`
	Options    Options  `yaml:"options"`
}

// RunnerConfig configures hook fan-out.
type RunnerConfig struct {
	Workers int
	Timeout time.Duration
	BaseDir string
	Logger  *slog.Logger
}

// PluginResult records one plugin invocation.
type PluginResult struct {
	Name     string
	Hook     Hook
	Outcome  Outcome
	Err      error
	Duration time.Duration

	// index is the plugin's position in the configured priority order.
	index int
}

// Result is the merged result of a hook.
type Result struct {
	Outcomes []PluginResult
	Decision Outcome
	TimedOut bool
	Duration time.Duration
}

// Rejected reports whether the hook produced a 4xx/5xx decision.
func (r Result) Rejected() bool {
	return r.Decision.Action == ActionReject || r.Decision.Action == ActionTempFail
}

// Entries returns the configured plugin names for diagnostics.
func (r *Runner) Entries() map[string][]string {
	out := make(map[string][]string)
	for hook, list := range r.hooks {
		for _, e := range list {
			out[string(hook)] = append(out[string(hook)], e.plugin.Name())
		}
	}
	return out
}

type entry struct {
	plugin     Plugin
	priority   int
	order      int
	timeout    time.Duration
	failClosed bool
}

// Runner constructs plugins and executes their hooks concurrently.
type Runner struct {
	logger  *slog.Logger
	workers int
	timeout time.Duration
	sem     chan struct{}
	hooks   map[Hook][]entry
}

// NewRunner builds all configured plugins. Any unknown plugin or invalid
// option aborts startup.
func NewRunner(defs []Definition, cfg RunnerConfig) (*Runner, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 8
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	r := &Runner{
		logger:  logger,
		workers: cfg.Workers,
		timeout: cfg.Timeout,
		sem:     make(chan struct{}, cfg.Workers),
		hooks:   make(map[Hook][]entry),
	}
	bc := BuildContext{BaseDir: cfg.BaseDir, Logger: logger}

	for i, def := range defs {
		if strings.TrimSpace(def.Name) == "" {
			return nil, fmt.Errorf("plugin %d: name is required", i+1)
		}
		if def.Enabled != nil && !*def.Enabled {
			continue
		}
		timeout := cfg.Timeout
		if def.Timeout != "" {
			d, err := time.ParseDuration(def.Timeout)
			if err != nil || d <= 0 {
				return nil, fmt.Errorf("plugin %s: invalid timeout %q", def.Name, def.Timeout)
			}
			timeout = d
		}
		p, err := New(def.Name, bc, def.Options)
		if err != nil {
			return nil, err
		}
		pluginHooks := p.Hooks()
		if len(pluginHooks) == 0 {
			return nil, fmt.Errorf("plugin %s declares no hooks", def.Name)
		}
		allowed := make(map[Hook]bool, len(pluginHooks))
		for _, h := range pluginHooks {
			if !h.Valid() {
				return nil, fmt.Errorf("plugin %s declares unknown hook %q", def.Name, h)
			}
			allowed[h] = true
		}
		selected := pluginHooks
		if len(def.Hooks) > 0 {
			parsed, err := ParseHooks(def.Hooks)
			if err != nil {
				return nil, fmt.Errorf("plugin %s: %w", def.Name, err)
			}
			selected = selected[:0]
			for _, h := range parsed {
				if !allowed[h] {
					return nil, fmt.Errorf("plugin %s: does not implement hook %q", def.Name, h)
				}
				selected = append(selected, h)
			}
		}
		failClosed := false
		if def.FailClosed != nil {
			failClosed = *def.FailClosed
		}
		for _, h := range selected {
			r.hooks[h] = append(r.hooks[h], entry{
				plugin:     p,
				priority:   def.Priority,
				order:      i,
				timeout:    timeout,
				failClosed: failClosed,
			})
		}
		logger.Debug("plugin loaded", "plugin", def.Name, "hooks", hookStrings(selected))
	}
	for hook := range r.hooks {
		sort.SliceStable(r.hooks[hook], func(i, j int) bool {
			a, b := r.hooks[hook][i], r.hooks[hook][j]
			if a.priority != b.priority {
				return a.priority < b.priority
			}
			return a.order < b.order
		})
	}
	return r, nil
}

func hookStrings(hooks []Hook) string {
	out := make([]string, len(hooks))
	for i, h := range hooks {
		out[i] = string(h)
	}
	return strings.Join(out, ",")
}

// Run executes every plugin registered for hook. Concurrent plugins run in
// parallel; plugins implementing Ordered then run one at a time in priority
// order. Individual plugin timeouts and the overall hook deadline are
// enforced.
func (r *Runner) Run(ctx context.Context, hook Hook, tx *Tx) Result {
	start := time.Now()
	entries := r.hooks[hook]
	if len(entries) == 0 {
		return Result{Decision: OK(), Duration: time.Since(start)}
	}

	runCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	var concurrent, ordered []indexedEntry
	for i, e := range entries {
		ie := indexedEntry{entry: e, index: i}
		if o, ok := e.plugin.(Ordered); ok && o.RunOrdered() {
			ordered = append(ordered, ie)
		} else {
			concurrent = append(concurrent, ie)
		}
	}

	res := Result{Outcomes: make([]PluginResult, 0, len(entries))}

	// Phase 1: run independent plugins concurrently.
	if len(concurrent) > 0 {
		results := make(chan PluginResult, len(concurrent))
		for _, ie := range concurrent {
			go func(ie indexedEntry) {
				pr := r.runOne(runCtx, ie, hook, tx)
				pr.index = ie.index
				results <- pr
			}(ie)
		}
		deadline := runCtx.Done()
	collect:
		for len(res.Outcomes) < len(concurrent) {
			select {
			case pr := <-results:
				res.Outcomes = append(res.Outcomes, pr)
			case <-deadline:
				res.TimedOut = true
				break collect
			}
		}
		sortResults(res.Outcomes)
		for i := range res.Outcomes {
			r.applyOutcome(tx, &res.Outcomes[i], false)
		}
	}

	// Flush headers scheduled by concurrent plugins into the message so
	// ordered plugins (especially DKIM signers) can see them.
	if len(ordered) > 0 {
		if hs := tx.TakeHeaders(); len(hs) > 0 {
			tx.Data = PrependHeaders(tx.Data, hs)
			tx.Size = int64(len(tx.Data))
		}
	}

	// Phase 2: run dependent/body-transforming plugins sequentially.
	for _, ie := range ordered {
		if err := runCtx.Err(); err != nil {
			res.TimedOut = true
			break
		}
		pr := r.runOne(runCtx, ie, hook, tx)
		pr.index = ie.index
		res.Outcomes = append(res.Outcomes, pr)
		r.applyOutcome(tx, &pr, true)
	}

	res.Duration = time.Since(start)
	sortResults(res.Outcomes)

	decision := OK()
	bestRank := -1
	for _, pr := range res.Outcomes {
		outcome := pr.Outcome
		if pr.Err != nil {
			outcome = ContinueOutcome()
			if e := r.entry(hook, pr.Name); e != nil && e.failClosed {
				outcome = TempFail(451, "4.7.1 Local policy check failed")
			}
		}
		if outcome.Action == ActionContinue {
			continue
		}
		if rank := actionRank(outcome.Action); rank > bestRank {
			decision = outcome
			bestRank = rank
		}
	}
	if res.TimedOut && bestRank < actionRank(ActionTempFail) {
		decision = TempFail(451, "4.7.0 Policy check timed out, please retry")
	}
	if decision.Action == ActionReject && decision.Code == 0 {
		decision.Code = 550
	}
	if decision.Action == ActionTempFail && decision.Code == 0 {
		decision.Code = 451
	}
	decision.Message = sanitizeMessage(decision.Message)
	res.Decision = decision
	return res
}

type indexedEntry struct {
	entry
	index int
}

// runOne executes a single plugin with panic recovery and timeout handling.
func (r *Runner) runOne(ctx context.Context, ie indexedEntry, hook Hook, tx *Tx) (pr PluginResult) {
	pr = PluginResult{Name: ie.plugin.Name(), Hook: hook, index: ie.index}
	if r.sem != nil {
		select {
		case r.sem <- struct{}{}:
			defer func() { <-r.sem }()
		case <-ctx.Done():
			pr.Err = ctx.Err()
			return
		}
	}
	pluginCtx, pluginCancel := context.WithTimeout(ctx, ie.timeout)
	defer pluginCancel()
	started := time.Now()
	defer func() {
		if rec := recover(); rec != nil {
			pr.Err = fmt.Errorf("panic: %v", rec)
		}
		pr.Duration = time.Since(started)
	}()
	pr.Outcome, pr.Err = ie.plugin.Run(pluginCtx, hook, tx)
	return
}

// applyOutcome merges metadata, tags, headers, and body changes into tx. When
// immediate is true headers are prepended to the message right away, which is
// required for ordered body transformers.
func (r *Runner) applyOutcome(tx *Tx, pr *PluginResult, immediate bool) {
	outcome := pr.Outcome
	if pr.Err != nil {
		level := slog.LevelWarn
		if pr.Err == context.DeadlineExceeded || pr.Err == context.Canceled {
			level = slog.LevelDebug
		}
		r.logger.Log(context.Background(), level, "plugin error", "plugin", pr.Name, "hook", pr.Hook, "error", pr.Err, "duration", pr.Duration)
		return
	}
	if pr.Outcome.Action != ActionContinue {
		r.logger.Debug("plugin decision", "plugin", pr.Name, "hook", pr.Hook, "action", pr.Outcome.Action, "code", pr.Outcome.Code, "message", pr.Outcome.Message, "duration", pr.Duration)
	}
	if immediate && len(outcome.Headers) > 0 {
		tx.Data = PrependHeaders(tx.Data, outcome.Headers)
		tx.Size = int64(len(tx.Data))
	} else {
		for _, h := range outcome.Headers {
			tx.AddHeader(h.Name, h.Value)
		}
	}
	for k, v := range outcome.Meta {
		tx.SetMeta(k, v)
	}
	for _, tag := range outcome.Tags {
		tx.SetMeta("tag."+tag, true)
	}
	if outcome.Body != nil {
		tx.Data = outcome.Body
		tx.Size = int64(len(outcome.Body))
	}
}

func sortResults(results []PluginResult) {
	sort.SliceStable(results, func(i, j int) bool { return results[i].index < results[j].index })
}

func (r *Runner) entry(hook Hook, name string) *entry {
	for i := range r.hooks[hook] {
		if r.hooks[hook][i].plugin.Name() == name {
			return &r.hooks[hook][i]
		}
	}
	return nil
}

// ContinueOutcome is an explicit no-op outcome.
func ContinueOutcome() Outcome { return Outcome{Action: ActionContinue} }

func actionRank(a Action) int {
	switch a {
	case ActionContinue:
		return 0
	case ActionAccept:
		return 1
	case ActionQuarantine:
		return 2
	case ActionDiscard:
		return 3
	case ActionTempFail:
		return 4
	case ActionReject:
		return 5
	default:
		return 0
	}
}

func sanitizeMessage(msg string) string {
	msg = strings.ReplaceAll(msg, "\r", " ")
	msg = strings.ReplaceAll(msg, "\n", " ")
	return strings.TrimSpace(msg)
}

// Workers returns the configured concurrency limit.
func (r *Runner) Workers() int { return r.workers }

// Timeout returns the overall per-hook timeout.
func (r *Runner) Timeout() time.Duration { return r.timeout }
