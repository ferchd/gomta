package delivery

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"github.com/ferchd/gomta/internal/boundedio"
	"github.com/ferchd/gomta/plugin"
)

func init() {
	Register("exec", NewExec)
}

// NewExec constructs a delivery backend that invokes an external command with
// a JSON envelope on stdin. Exit code 0 is success, 75 means temporary failure,
// and any other non-zero code is permanent.
func NewExec(bc plugin.BuildContext, opts plugin.Options) (Backend, error) {
	command := opts.String("command", "")
	if command == "" {
		return nil, fmt.Errorf("command is required")
	}
	return &execBackend{
		dir:     bc.BaseDir,
		command: command,
		args:    opts.Strings("args"),
		timeout: opts.Duration("timeout", 2*time.Minute),
	}, nil
}

type execBackend struct {
	dir     string
	command string
	args    []string
	timeout time.Duration
}

func (b *execBackend) Name() string { return "exec" }

type execDeliveryRequest struct {
	ID       string            `json:"id"`
	From     string            `json:"from"`
	To       []string          `json:"to"`
	Mode     string            `json:"mode,omitempty"`
	Helo     string            `json:"helo,omitempty"`
	RemoteIP string            `json:"remote_ip,omitempty"`
	Meta     map[string]string `json:"meta,omitempty"`
	Message  string            `json:"message_base64"`
}

func (b *execBackend) Deliver(ctx context.Context, m *Message) map[string]error {
	results := make(map[string]error, len(m.To))
	payload, err := json.Marshal(execDeliveryRequest{
		ID:       m.ID,
		From:     m.From,
		To:       m.To,
		Mode:     m.Mode,
		Helo:     m.Helo,
		RemoteIP: m.RemoteIP,
		Meta:     m.Meta,
		Message:  base64.StdEncoding.EncodeToString(m.Data),
	})
	if err != nil {
		for _, rcpt := range m.To {
			results[rcpt] = Perm(err)
		}
		return results
	}
	runCtx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, b.command, b.args...)
	cmd.Dir = b.dir
	cmd.Stdin = bytes.NewReader(payload)
	stderr := &boundedio.Truncate{Max: 64 << 10}
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		var e error
		var exitErr *exec.ExitError
		switch {
		case runCtx.Err() != nil:
			e = Temp(fmt.Errorf("exec backend interrupted: %w", runCtx.Err()))
		case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
			e = Temp(err)
		case errors.As(err, &exitErr) && exitErr.ExitCode() == 75:
			e = Temp(fmt.Errorf("exec backend temporary failure: %s", stderr.String()))
		default:
			e = Perm(fmt.Errorf("exec backend failed: %v: %s", err, stderr.String()))
		}
		for _, rcpt := range m.To {
			results[rcpt] = e
		}
		return results
	}
	for _, rcpt := range m.To {
		results[rcpt] = nil
	}
	return results
}
