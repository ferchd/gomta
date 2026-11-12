package delivery

import (
	"context"

	"github.com/ferchd/gomta/plugin"
)

func init() {
	Register("discard", NewDiscard)
}

// NewDiscard constructs a backend that accepts and drops every message.
func NewDiscard(bc plugin.BuildContext, opts plugin.Options) (Backend, error) {
	return discardBackend{}, nil
}

type discardBackend struct{}

func (discardBackend) Name() string { return "discard" }

func (discardBackend) Deliver(ctx context.Context, m *Message) map[string]error {
	out := make(map[string]error, len(m.To))
	for _, rcpt := range m.To {
		out[rcpt] = nil
	}
	return out
}
