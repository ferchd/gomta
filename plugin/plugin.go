// Package plugin defines the hook API used by GoMTA.
//
// A plugin receives a read-mostly view of the current SMTP transaction and
// returns an Outcome. Plugins for the same hook are always executed
// concurrently, so slow DNS, Redis, HTTP, or antivirus calls do not serialize
// other plugins. Outcomes are merged deterministically by plugin priority.
package plugin

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"net/textproto"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Hook identifies an SMTP lifecycle event.
type Hook string

const (
	HookConnect    Hook = "connect"
	HookHelo       Hook = "helo"
	HookMail       Hook = "mail"
	HookRcpt       Hook = "rcpt"
	HookData       Hook = "data"
	HookQueue      Hook = "queue"
	HookDelivery   Hook = "delivery"
	HookDisconnect Hook = "disconnect"
)

var allHooks = []Hook{
	HookConnect, HookHelo, HookMail, HookRcpt, HookData,
	HookQueue, HookDelivery, HookDisconnect,
}

// Hooks returns every built-in hook name.
func Hooks() []Hook {
	out := make([]Hook, len(allHooks))
	copy(out, allHooks)
	return out
}

// Valid reports whether h is a known hook.
func (h Hook) Valid() bool {
	for _, v := range allHooks {
		if h == v {
			return true
		}
	}
	return false
}

// String implements fmt.Stringer.
func (h Hook) String() string { return string(h) }

// ParseHooks converts and validates hook names.
func ParseHooks(names []string) ([]Hook, error) {
	out := make([]Hook, 0, len(names))
	for _, name := range names {
		h := Hook(strings.ToLower(strings.TrimSpace(name)))
		if !h.Valid() {
			return nil, fmt.Errorf("unknown hook %q (valid: %s)", name, hookNames())
		}
		out = append(out, h)
	}
	return out, nil
}

func hookNames() string {
	names := make([]string, len(allHooks))
	for i, h := range allHooks {
		names[i] = string(h)
	}
	return strings.Join(names, ", ")
}

// Mode describes the listener that accepted a message.
type Mode string

const (
	ModeMTA        Mode = "mta"
	ModeSubmission Mode = "submission"
	ModeFilter     Mode = "filter"
)

// Valid reports whether m is a known listener mode.
func (m Mode) Valid() bool {
	return m == ModeMTA || m == ModeSubmission || m == ModeFilter
}

// Action is a plugin verdict.
type Action int

const (
	// ActionContinue means the plugin has no objection.
	ActionContinue Action = iota
	// ActionAccept explicitly accepts the transaction. Other rejections still win.
	ActionAccept
	// ActionQuarantine asks the core to store the message without delivering it.
	ActionQuarantine
	// ActionDiscard asks the core to accept and silently drop the message.
	ActionDiscard
	// ActionTempFail asks the client to retry later (4xx).
	ActionTempFail
	// ActionReject permanently rejects the transaction (5xx).
	ActionReject
)

func (a Action) String() string {
	switch a {
	case ActionContinue:
		return "continue"
	case ActionAccept:
		return "accept"
	case ActionQuarantine:
		return "quarantine"
	case ActionDiscard:
		return "discard"
	case ActionTempFail:
		return "tempfail"
	case ActionReject:
		return "reject"
	default:
		return fmt.Sprintf("action(%d)", int(a))
	}
}

// Outcome is the result of running one plugin.
type Outcome struct {
	Action  Action
	Code    int
	Message string
	// Headers are appended to the message header block for data/queue hooks.
	Headers []Header
	// Body replaces the current message body for data/queue hooks.
	Body []byte
	// Meta is merged into the transaction metadata.
	Meta map[string]any
	// Tags are diagnostic labels, e.g. "spam" or "dkim-verified".
	Tags []string
}

// Header is a single RFC 5322 header field.
type Header struct {
	Name  string
	Value string
}

// Reject builds a permanent rejection outcome.
func Reject(code int, format string, args ...any) Outcome {
	if code == 0 {
		code = 550
	}
	return Outcome{Action: ActionReject, Code: code, Message: fmt.Sprintf(format, args...)}
}

// TempFail builds a temporary rejection outcome.
func TempFail(code int, format string, args ...any) Outcome {
	if code == 0 {
		code = 451
	}
	return Outcome{Action: ActionTempFail, Code: code, Message: fmt.Sprintf(format, args...)}
}

// OK builds a ActionContinue outcome.
func OK() Outcome { return Outcome{Action: ActionContinue} }

// Tx is the transaction passed to plugins. Fields are read-only after the
// transaction reaches a hook; metadata and added headers are synchronized.
type Tx struct {
	ID           string
	RemoteIP     net.IP
	RemoteIPs    []net.IP
	RemoteAddr   string
	Helo         string
	TLS          bool
	TLSVersion   string
	AuthUser     string
	MailFrom     string
	RcptTo       []string
	Recipient    string
	Data         []byte
	Header       textproto.MIMEHeader
	Size         int64
	MaxBodyBytes int64 // maximum permitted data after transformations, zero = unrestricted
	Mode         Mode
	ServerName   string
	Arrived      time.Time

	mu           sync.RWMutex
	meta         map[string]any
	headers      []Header
	bodyLease    *BodyLease
	senderPolicy func(string) bool // parent-only authenticated sender validator
}

// NewTx returns an empty transaction.
func NewTx() *Tx {
	return &Tx{
		Header:  make(textproto.MIMEHeader),
		Arrived: time.Now(),
		meta:    make(map[string]any),
	}
}

// SetBody transfers an optional retained output lease. Replacing the body
// releases the old buffer reservation once the replacement is ready.
func (t *Tx) SetBody(data []byte, lease *BodyLease) {
	if t.bodyLease != nil && t.bodyLease != lease {
		t.bodyLease.Release()
	}
	t.bodyLease = lease
	t.Data = data
	t.Size = int64(len(data))
}

// ApplyHeaders charges for both live buffers while prepending headers.
// It replaces the old reservation only after the new buffer has been copied.
func (t *Tx) ApplyHeaders(headers []Header) error {
	if len(headers) == 0 {
		return nil
	}
	prefixed := PrependHeaders([]byte{0}, headers)
	prefix := prefixed[:len(prefixed)-1]
	if len(prefix) == 0 {
		return nil
	}
	if t.bodyLease == nil || t.bodyLease.budget == nil {
		t.SetBody(PrependHeaders(t.Data, headers), nil)
		return nil
	}
	newSize := int64(len(prefix)) + int64(len(t.Data))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	budget := t.bodyLease.budget
	if err := budget.Acquire(ctx, newSize); err != nil {
		return fmt.Errorf("%w: header expansion: %v", ErrBudgetExceeded, err)
	}
	body := make([]byte, int(newSize))
	copy(body, prefix)
	copy(body[len(prefix):], t.Data)
	t.SetBody(body, &BodyLease{budget: budget, size: newSize})
	return nil
}

// SetSenderPolicy binds the authenticated policy only to the parent Tx.
// Filter snapshots do not receive the validator and cannot disable it.
func (t *Tx) SetSenderPolicy(allowed func(string) bool) { t.senderPolicy = allowed }

// ValidSender verifies the current message after body-changing plugins.
func (t *Tx) ValidSender() bool {
	if t.senderPolicy == nil {
		return true
	}
	from := ParseHeaders(t.Data)["from"]
	if len(from) != 1 {
		return false
	}
	addrs, err := mail.ParseAddressList(from[0])
	return err == nil && len(addrs) == 1 && t.senderPolicy(addrs[0].Address)
}

// Close releases retained output and drops DATA when a transaction ends.
func (t *Tx) Close() { t.SetBody(nil, nil) }

// OutputReservation declares maximum retained subprocess output. The runner
// acquires it together with the DATA snapshot, preventing nested deadlocks.
type OutputReservation interface{ OutputReservationBytes() int64 }

// SetMeta stores a value shared with later hooks and plugins.
func (t *Tx) SetMeta(key string, value any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.meta == nil {
		t.meta = make(map[string]any)
	}
	t.meta[key] = value
}

// Meta returns a metadata value.
func (t *Tx) Meta(key string) (any, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	v, ok := t.meta[key]
	return v, ok
}

// MetaString returns a metadata value as a string.
func (t *Tx) MetaString(key string) string {
	v, ok := t.Meta(key)
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

// MetaSnapshot returns a copy of the metadata map.
func (t *Tx) MetaSnapshot() map[string]any {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[string]any, len(t.meta))
	for k, v := range t.meta {
		out[k] = v
	}
	return out
}

// AddHeader schedules a header to be prepended by the core. Safe for
// concurrent use.
func (t *Tx) AddHeader(name, value string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.headers = append(t.headers, Header{Name: name, Value: value})
}

// AddedHeaders returns a copy of headers scheduled with AddHeader.
func (t *Tx) AddedHeaders() []Header {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]Header, len(t.headers))
	copy(out, t.headers)
	return out
}

// TakeHeaders returns and clears headers scheduled with AddHeader.
func (t *Tx) TakeHeaders() []Header {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Header, len(t.headers))
	copy(out, t.headers)
	t.headers = nil
	return out
}

// Plugin is implemented by every hook processor.
type Plugin interface {
	// Name is the stable plugin identifier used in configuration.
	Name() string
	// Hooks lists the hooks the plugin wants to receive.
	Hooks() []Hook
	// Run processes one hook. It must honor ctx cancellation.
	Run(ctx context.Context, hook Hook, tx *Tx) (Outcome, error)
}

// Ordered is an optional interface for plugins that must run after every
// concurrent plugin for the same hook, one at a time in priority order.
//
// Use it when a plugin depends on metadata produced by another plugin (for
// example DMARC consuming DKIM and SPF results) or when it rewrites the
// message body and needs to see the output of earlier transformers. A
// sequential plugin sees headers and body changes made by concurrent plugins
// and by lower-priority sequential plugins.
type Ordered interface {
	RunOrdered() bool
}

// Factory constructs a plugin from its YAML options.
type Factory func(bc BuildContext, opts Options) (Plugin, error)

// BuildContext carries host configuration into a plugin.
type BuildContext struct {
	BaseDir string
	Logger  *slog.Logger
	Budget  *ByteBudget // shared snapshot and external-filter output budget
}

// Path resolves a possibly relative path against the configuration directory.
func (bc BuildContext) Path(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	if strings.HasPrefix(p, "~/") {
		if home, err := homeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return filepath.Join(bc.BaseDir, p)
}

// Registry stores plugin factories.
type Registry struct {
	mu        sync.RWMutex
	factories map[string]Factory
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{factories: make(map[string]Factory)}
}

// Default is the process-wide plugin registry used by configuration.
var Default = NewRegistry()

// Register adds a plugin factory to the default registry. It panics on
// duplicate names or nil factories, because both are programming errors.
func Register(name string, f Factory) { Default.Register(name, f) }

// Register adds a plugin factory to r.
func (r *Registry) Register(name string, f Factory) {
	if name == "" {
		panic("plugin: empty plugin name")
	}
	if f == nil {
		panic("plugin: nil factory for " + name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.factories[name]; exists {
		panic("plugin: duplicate registration for " + name)
	}
	r.factories[name] = f
}

// Names returns registered plugin names sorted alphabetically.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.factories))
	for name := range r.factories {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// New constructs a plugin from the default registry.
func New(name string, bc BuildContext, opts Options) (Plugin, error) {
	return Default.New(name, bc, opts)
}

// New constructs a plugin from r.
func (r *Registry) New(name string, bc BuildContext, opts Options) (Plugin, error) {
	r.mu.RLock()
	f, ok := r.factories[name]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown plugin %q (available: %s)", name, strings.Join(r.Names(), ", "))
	}
	if opts == nil {
		opts = Options{}
	}
	p, err := f(bc, opts)
	if err != nil {
		return nil, fmt.Errorf("plugin %s: %w", name, err)
	}
	if p == nil {
		return nil, fmt.Errorf("plugin %s: factory returned nil", name)
	}
	return p, nil
}
