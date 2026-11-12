// Package helo validates the EHLO/HELO argument.
package helo

import (
	"context"
	"net"
	"strings"

	"github.com/ferchd/gomta/plugin"
)

func init() {
	plugin.Register("helo", func(bc plugin.BuildContext, opts plugin.Options) (plugin.Plugin, error) {
		return &Plugin{
			rejectInvalid:   opts.Bool("reject_invalid", false),
			rejectLocalhost: opts.Bool("reject_localhost", false),
			allowIPLiterals: opts.Bool("allow_ip_literals", true),
			skipSubmission:  opts.Bool("skip_submission", true),
			minLabels:       opts.Int("min_labels", 2),
		}, nil
	})
}

// Plugin implements the helo hook.
type Plugin struct {
	rejectInvalid   bool
	rejectLocalhost bool
	allowIPLiterals bool
	skipSubmission  bool
	minLabels       int
}

func (p *Plugin) Name() string { return "helo" }

func (p *Plugin) Hooks() []plugin.Hook { return []plugin.Hook{plugin.HookHelo} }

func (p *Plugin) Run(ctx context.Context, hook plugin.Hook, tx *plugin.Tx) (plugin.Outcome, error) {
	if p.skipSubmission && tx.Mode == plugin.ModeSubmission {
		return plugin.OK(), nil
	}
	helo := strings.TrimSpace(tx.Helo)
	reason := ""
	switch {
	case helo == "":
		reason = "empty HELO"
	case strings.HasPrefix(helo, "[") && strings.HasSuffix(helo, "]"):
		if !p.allowIPLiterals {
			reason = "IP literals are not allowed in HELO"
			break
		}
		if net.ParseIP(strings.Trim(helo, "[]")) == nil {
			reason = "malformed IP literal"
		}
	case strings.EqualFold(helo, "localhost") || strings.EqualFold(helo, "localhost.localdomain"):
		if p.rejectLocalhost {
			reason = "localhost is not a valid HELO name"
		}
	case strings.ContainsAny(helo, " \t/\\"):
		reason = "malformed HELO"
	default:
		labels := strings.Split(strings.TrimSuffix(helo, "."), ".")
		if p.minLabels > 1 && len(labels) < p.minLabels {
			reason = "HELO is not a fully-qualified domain name"
		}
	}
	if reason == "" && p.minLabels > 1 && net.ParseIP(helo) != nil {
		reason = "HELO must be a domain name"
	}
	tx.SetMeta("helo.valid", reason == "")
	if reason != "" {
		tx.SetMeta("helo.reason", reason)
		if p.rejectInvalid {
			return plugin.Reject(550, "5.7.1 Invalid HELO: %s", reason), nil
		}
	}
	return plugin.OK(), nil
}
