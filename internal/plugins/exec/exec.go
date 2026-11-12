// Package exec runs an external command as a message filter.
package exec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ferchd/gomta/plugin"
)

func init() {
	plugin.Register("exec", func(bc plugin.BuildContext, opts plugin.Options) (plugin.Plugin, error) {
		command := strings.TrimSpace(opts.String("command", ""))
		if command == "" {
			return nil, fmt.Errorf("command is required")
		}
		p := &Plugin{
			command:         command,
			args:            opts.Strings("args"),
			env:             opts.Map("env"),
			timeout:         opts.Duration("timeout", 30*time.Second),
			replaceBody:     opts.Bool("replace_body", true),
			tempfailOnError: opts.Bool("tempfail_on_error", true),
			maxOutput:       opts.Int("max_output_bytes", 64<<20),
			rejectMessage:   opts.String("reject_message", "Message rejected by content filter"),
			tempfailMessage: opts.String("tempfail_message", "Content filter temporarily unavailable, try again"),
			logger:          bc.Logger,
		}
		if p.timeout <= 0 {
			p.timeout = 30 * time.Second
		}
		p.acceptCodes = intList(opts, "accept_codes", []int{0})
		p.tempfailCodes = intList(opts, "tempfail_codes", []int{75})
		return p, nil
	})
}

// Plugin implements the data hook.
type Plugin struct {
	command         string
	args            []string
	env             plugin.Options
	timeout         time.Duration
	replaceBody     bool
	tempfailOnError bool
	maxOutput       int
	acceptCodes     []int
	tempfailCodes   []int
	rejectMessage   string
	tempfailMessage string
	logger          *slog.Logger
}

// Name implements plugin.Plugin.
func (p *Plugin) Name() string { return "exec" }

// Hooks implements plugin.Plugin.
func (p *Plugin) Hooks() []plugin.Hook { return []plugin.Hook{plugin.HookData} }

// RunOrdered ensures the filter sees the message after other transformations
// and its body replacement is applied in order.
func (p *Plugin) RunOrdered() bool { return true }

// Run implements plugin.Plugin.
func (p *Plugin) Run(ctx context.Context, hook plugin.Hook, tx *plugin.Tx) (plugin.Outcome, error) {
	runCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, p.command, p.args...)
	cmd.Stdin = bytes.NewReader(tx.Data)
	cmd.Env = append(os.Environ(), p.environment(hook, tx)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.WaitDelay = 5 * time.Second

	err := cmd.Run()
	if runCtx.Err() != nil {
		return p.failure(tx, "timeout", runCtx.Err())
	}
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return p.failure(tx, "start", err)
		}
		code := exitErr.ExitCode()
		if containsInt(p.acceptCodes, code) {
			return p.success(tx, stdout.Bytes())
		}
		if p.logger != nil {
			p.logger.Debug("exec filter exited", "queue_id", tx.ID, "code", code, "stderr", snippet(stderr.Bytes()))
		}
		tx.SetMeta("exec.exit_code", code)
		if containsInt(p.tempfailCodes, code) {
			return plugin.TempFail(451, "4.7.1 %s", p.tempfailMessage), nil
		}
		return plugin.Reject(550, "5.7.1 %s (exit %d)", p.rejectMessage, code), nil
	}
	return p.success(tx, stdout.Bytes())
}

func (p *Plugin) success(tx *plugin.Tx, stdout []byte) (plugin.Outcome, error) {
	tx.SetMeta("exec.exit_code", 0)
	if !p.replaceBody || len(stdout) == 0 {
		return plugin.OK(), nil
	}
	if p.maxOutput > 0 && len(stdout) > p.maxOutput {
		return p.failure(tx, "output", fmt.Errorf("output exceeds %d bytes", p.maxOutput))
	}
	return plugin.Outcome{Action: plugin.ActionContinue, Body: stdout}, nil
}

func (p *Plugin) failure(tx *plugin.Tx, stage string, err error) (plugin.Outcome, error) {
	tx.SetMeta("exec.error", err.Error())
	if p.logger != nil {
		p.logger.Warn("exec filter failed", "queue_id", tx.ID, "stage", stage, "error", err)
	}
	if p.tempfailOnError {
		return plugin.TempFail(451, "4.7.1 %s", p.tempfailMessage), nil
	}
	return plugin.OK(), nil
}

func (p *Plugin) environment(hook plugin.Hook, tx *plugin.Tx) []string {
	env := []string{
		"GOMTA_HOOK=" + string(hook),
		"GOMTA_QUEUE_ID=" + tx.ID,
		"GOMTA_FROM=" + tx.MailFrom,
		"GOMTA_RCPT=" + strings.Join(tx.RcptTo, ","),
		"GOMTA_HELO=" + tx.Helo,
		"GOMTA_REMOTE_ADDR=" + tx.RemoteAddr,
		"GOMTA_AUTH_USER=" + tx.AuthUser,
		"GOMTA_MODE=" + string(tx.Mode),
		"GOMTA_SERVER_NAME=" + tx.ServerName,
		"GOMTA_TLS=" + strconv.FormatBool(tx.TLS),
		"GOMTA_SIZE=" + strconv.FormatInt(tx.Size, 10),
	}
	if tx.RemoteIP != nil {
		env = append(env, "GOMTA_REMOTE_IP="+tx.RemoteIP.String())
	}
	for key, value := range p.env {
		env = append(env, key+"="+fmt.Sprint(value))
	}
	return env
}

func intList(opts plugin.Options, key string, def []int) []int {
	raw := opts.Strings(key)
	if len(raw) == 0 {
		return def
	}
	out := make([]int, 0, len(raw))
	for _, s := range raw {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			continue
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return def
	}
	return out
}

func containsInt(list []int, n int) bool {
	for _, v := range list {
		if v == n {
			return true
		}
	}
	return false
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 500 {
		s = s[:500] + "..."
	}
	return s
}
