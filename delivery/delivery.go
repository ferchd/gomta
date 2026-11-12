// Package delivery implements message delivery backends and a registry for
// custom backends.
package delivery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"

	"github.com/ferchd/gomta/plugin"
)

// Message is the delivery unit handed to a backend.
type Message struct {
	ID       string
	From     string
	To       []string
	Data     []byte
	Meta     map[string]string
	Mode     string
	Helo     string
	RemoteIP string
}

// Backend delivers a message to one or more recipients. It returns a map with
// one entry per recipient. A nil error means success.
type Backend interface {
	Name() string
	Deliver(ctx context.Context, m *Message) map[string]error
}

// Error is a delivery failure with SMTP-ish semantics.
type Error struct {
	Code      int
	Temporary bool
	Err       error
}

// Error implements error.
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	if e.Code != 0 {
		return fmt.Sprintf("delivery failed with code %d", e.Code)
	}
	return "delivery failed"
}

// Unwrap exposes the underlying error.
func (e *Error) Unwrap() error { return e.Err }

// Temp marks an error as temporary (retry later).
func Temp(err error) error {
	if err == nil {
		return nil
	}
	var de *Error
	if errors.As(err, &de) && de.Temporary {
		return err
	}
	return &Error{Temporary: true, Err: err}
}

// Perm marks an error as permanent.
func Perm(err error) error {
	if err == nil {
		return nil
	}
	return &Error{Temporary: false, Err: err}
}

// IsTemporary reports whether err should be retried.
func IsTemporary(err error) bool {
	if err == nil {
		return false
	}
	var de *Error
	if errors.As(err, &de) {
		return de.Temporary
	}
	return true
}

// Factory constructs a backend from YAML options.
type Factory func(bc plugin.BuildContext, opts plugin.Options) (Backend, error)

// Registry stores delivery backend factories.
type Registry struct {
	mu        sync.RWMutex
	factories map[string]Factory
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{factories: make(map[string]Factory)} }

// Default is the process-wide delivery registry.
var Default = NewRegistry()

// Register adds a backend factory to the default registry.
func Register(name string, f Factory) { Default.Register(name, f) }

// Register adds a backend factory to r.
func (r *Registry) Register(name string, f Factory) {
	if name == "" {
		panic("delivery: empty backend name")
	}
	if f == nil {
		panic("delivery: nil factory for " + name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.factories[name]; exists {
		panic("delivery: duplicate registration for " + name)
	}
	r.factories[name] = f
}

// Names returns registered backend names sorted.
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

// New constructs a backend from the default registry.
func New(name string, bc plugin.BuildContext, opts plugin.Options) (Backend, error) {
	return Default.New(name, bc, opts)
}

// New constructs a backend from r.
func (r *Registry) New(name string, bc plugin.BuildContext, opts plugin.Options) (Backend, error) {
	r.mu.RLock()
	f, ok := r.factories[name]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown delivery backend %q (available: %s)", name, strings.Join(r.Names(), ", "))
	}
	if opts == nil {
		opts = plugin.Options{}
	}
	b, err := f(bc, opts)
	if err != nil {
		return nil, fmt.Errorf("delivery backend %s: %w", name, err)
	}
	if b == nil {
		return nil, fmt.Errorf("delivery backend %s: factory returned nil", name)
	}
	return b, nil
}

// Logger returns a usable logger.
func Logger(bc plugin.BuildContext) *slog.Logger {
	if bc.Logger != nil {
		return bc.Logger
	}
	return slog.Default()
}
