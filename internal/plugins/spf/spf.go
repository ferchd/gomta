// Package spf imports SPF results into the transaction and optionally rejects
// failures.
package spf

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/ferchd/gomta/internal/spf"
	"github.com/ferchd/gomta/plugin"
)

func init() {
	plugin.Register("spf", func(bc plugin.BuildContext, opts plugin.Options) (plugin.Plugin, error) {
		p := &Plugin{
			rejectFail:        opts.Bool("reject_fail", false),
			rejectSoftFail:    opts.Bool("reject_softfail", false),
			rejectNone:        opts.Bool("reject_none", false),
			tempfailOnError:   opts.Bool("tempfail_on_error", false),
			skipAuthenticated: opts.Bool("skip_authenticated", true),
			skipSubmission:    opts.Bool("skip_submission", true),
			logger:            bc.Logger,
		}
		for _, raw := range opts.Strings("trusted_networks") {
			_, n, err := net.ParseCIDR(raw)
			if err != nil {
				return nil, fmt.Errorf("trusted_networks: %w", err)
			}
			p.trusted = append(p.trusted, n)
		}
		return p, nil
	})
}

// Plugin implements the mail hook.
type Plugin struct {
	rejectFail        bool
	rejectSoftFail    bool
	rejectNone        bool
	tempfailOnError   bool
	skipAuthenticated bool
	skipSubmission    bool
	trusted           []*net.IPNet
	logger            *slog.Logger
}

func (p *Plugin) Name() string { return "spf" }

func (p *Plugin) Hooks() []plugin.Hook { return []plugin.Hook{plugin.HookMail} }

func (p *Plugin) Run(ctx context.Context, hook plugin.Hook, tx *plugin.Tx) (plugin.Outcome, error) {
	if p.skipAuthenticated && tx.AuthUser != "" {
		tx.SetMeta("spf.result", "none")
		return plugin.OK(), nil
	}
	if p.skipSubmission && tx.Mode == plugin.ModeSubmission {
		tx.SetMeta("spf.result", "none")
		return plugin.OK(), nil
	}
	if tx.RemoteIP == nil {
		return plugin.OK(), nil
	}
	for _, n := range p.trusted {
		if n.Contains(tx.RemoteIP) {
			tx.SetMeta("spf.result", "trusted")
			return plugin.OK(), nil
		}
	}
	identity := tx.MailFrom
	if identity == "" {
		identity = tx.Helo
	}
	result := spf.New().Check(ctx, tx.RemoteIP, tx.Helo, identity)
	tx.SetMeta("spf.result", string(result.Result))
	tx.SetMeta("spf.domain", result.Domain)
	tx.SetMeta("spf.identity", result.Identity)
	if result.Explanation != "" {
		tx.SetMeta("spf.explanation", result.Explanation)
	}
	if p.logger != nil {
		p.logger.Debug("SPF result", "queue_id", tx.ID, "domain", result.Domain, "identity", result.Identity, "result", result.Result)
	}
	switch result.Result {
	case spf.Fail:
		if p.rejectFail {
			return plugin.Reject(550, "5.7.1 SPF fail for %s", result.Domain), nil
		}
	case spf.SoftFail:
		if p.rejectSoftFail {
			return plugin.Reject(550, "5.7.1 SPF softfail for %s", result.Domain), nil
		}
	case spf.None:
		if p.rejectNone {
			return plugin.Reject(550, "5.7.1 No SPF record for %s", result.Domain), nil
		}
	case spf.TempError, spf.PermError:
		if p.tempfailOnError {
			return plugin.TempFail(451, "4.7.1 SPF lookup failed for %s", result.Domain), nil
		}
	}
	return plugin.OK(), nil
}
