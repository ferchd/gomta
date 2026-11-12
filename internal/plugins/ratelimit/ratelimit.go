// Package ratelimit applies per-IP, per-user, or per-sender message rate limits
// using Redis or an in-process store.
package ratelimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/ferchd/gomta/internal/kv"
	"github.com/ferchd/gomta/plugin"
)

func init() {
	plugin.Register("rate_limit", func(bc plugin.BuildContext, opts plugin.Options) (plugin.Plugin, error) {
		store, err := kv.Open(opts.String("redis_url", ""))
		if err != nil {
			return nil, fmt.Errorf("open store: %w", err)
		}
		action := strings.ToLower(opts.String("action", "tempfail"))
		if action != "tempfail" && action != "reject" {
			return nil, fmt.Errorf("action must be tempfail or reject")
		}
		p := &Plugin{
			store:             store,
			limit:             opts.Int("limit", 200),
			window:            opts.Duration("window", time.Hour),
			scope:             strings.ToLower(opts.String("scope", "smart")),
			action:            action,
			code:              opts.Int("code", 0),
			skipAuthenticated: opts.Bool("skip_authenticated", false),
			failClosed:        opts.Bool("fail_closed", true),
			logger:            bc.Logger,
		}
		if p.window <= 0 {
			p.window = time.Hour
		}
		switch p.scope {
		case "ip", "auth", "sender", "ip+sender", "smart":
		default:
			return nil, fmt.Errorf("scope must be ip, auth, sender, ip+sender or smart")
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
	store             kv.Store
	limit             int
	window            time.Duration
	scope             string
	action            string
	code              int
	skipAuthenticated bool
	failClosed        bool
	trusted           []*net.IPNet
	logger            *slog.Logger
}

func (p *Plugin) Name() string { return "rate_limit" }

func (p *Plugin) Hooks() []plugin.Hook { return []plugin.Hook{plugin.HookMail} }

func (p *Plugin) Run(ctx context.Context, hook plugin.Hook, tx *plugin.Tx) (plugin.Outcome, error) {
	if p.limit <= 0 {
		return plugin.OK(), nil
	}
	if p.skipAuthenticated && tx.AuthUser != "" {
		return plugin.OK(), nil
	}
	for _, n := range p.trusted {
		if tx.RemoteIP != nil && n.Contains(tx.RemoteIP) {
			return plugin.OK(), nil
		}
	}
	value := p.keyValue(tx)
	if value == "" {
		return plugin.OK(), nil
	}
	hash := sha256.Sum256([]byte(value))
	key := "gomta:ratelimit:" + p.scope + ":" + hex.EncodeToString(hash[:12])
	count, err := p.store.Incr(ctx, key, p.window)
	if err != nil {
		if p.logger != nil {
			p.logger.Warn("rate limit store error", "error", err, "fail_closed", p.failClosed)
		}
		if p.failClosed {
			return plugin.TempFail(451, "4.7.1 Rate limit service unavailable"), nil
		}
		return plugin.OK(), nil
	}
	tx.SetMeta("rate_limit.count", count)
	tx.SetMeta("rate_limit.limit", p.limit)
	if count <= int64(p.limit) {
		return plugin.OK(), nil
	}
	code := p.code
	if code == 0 {
		if p.action == "reject" {
			code = 550
		} else {
			code = 451
		}
	}
	msg := fmt.Sprintf("4.7.0 Rate limit exceeded (%d/%d per %s)", count, p.limit, p.window)
	if p.action == "reject" {
		return plugin.Reject(code, "5.7.1 Rate limit exceeded"), nil
	}
	return plugin.TempFail(code, "%s", msg), nil
}

func (p *Plugin) keyValue(tx *plugin.Tx) string {
	ip := ""
	if tx.RemoteIP != nil {
		ip = tx.RemoteIP.String()
	}
	switch p.scope {
	case "smart":
		if tx.AuthUser != "" {
			return "auth:" + strings.ToLower(tx.AuthUser)
		}
		// Unauthenticated clients control MAIL FROM; aggregate solely by IP
		// so rotating sender addresses cannot reset the abuse budget.
		return "ip:" + ip
	case "auth":
		if tx.AuthUser != "" {
			return tx.AuthUser
		}
		return ip
	case "sender":
		return plugin.NormalizeAddress(tx.MailFrom)
	case "ip+sender":
		return ip + "|" + plugin.NormalizeAddress(tx.MailFrom)
	default:
		return ip
	}
}
