// Package greylist implements classic SMTP greylisting with Redis or memory.
package greylist

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/ferchd/gomta/internal/kv"
	"github.com/ferchd/gomta/plugin"
)

func init() {
	plugin.Register("greylist", func(bc plugin.BuildContext, opts plugin.Options) (plugin.Plugin, error) {
		store, err := kv.Open(opts.String("redis_url", ""))
		if err != nil {
			return nil, fmt.Errorf("open store: %w", err)
		}
		p := &Plugin{
			store:                  store,
			delay:                  opts.Duration("delay", 5*time.Minute),
			passTTL:                opts.Duration("pass_ttl", 36*24*time.Hour),
			whitelistAuthenticated: opts.Bool("whitelist_authenticated", true),
			logger:                 bc.Logger,
		}
		if p.delay <= 0 {
			p.delay = 5 * time.Minute
		}
		if p.passTTL <= 0 {
			p.passTTL = 36 * 24 * time.Hour
		}
		for _, raw := range opts.Strings("whitelist_networks") {
			_, n, err := net.ParseCIDR(raw)
			if err != nil {
				return nil, fmt.Errorf("whitelist_networks: %w", err)
			}
			p.trusted = append(p.trusted, n)
		}
		return p, nil
	})
}

// Plugin implements the rcpt hook.
type Plugin struct {
	store                  kv.Store
	delay                  time.Duration
	passTTL                time.Duration
	whitelistAuthenticated bool
	trusted                []*net.IPNet
	logger                 *slog.Logger
}

func (p *Plugin) Name() string { return "greylist" }

func (p *Plugin) Hooks() []plugin.Hook { return []plugin.Hook{plugin.HookRcpt} }

func (p *Plugin) Run(ctx context.Context, hook plugin.Hook, tx *plugin.Tx) (plugin.Outcome, error) {
	if p.whitelistAuthenticated && tx.AuthUser != "" {
		return plugin.OK(), nil
	}
	for _, n := range p.trusted {
		if tx.RemoteIP != nil && n.Contains(tx.RemoteIP) {
			return plugin.OK(), nil
		}
	}
	ip := ""
	if tx.RemoteIP != nil {
		ip = tx.RemoteIP.String()
	}
	sum := sha256.Sum256([]byte(ip + "|" + plugin.NormalizeAddress(tx.MailFrom) + "|" + plugin.NormalizeAddress(tx.Recipient)))
	key := "gomta:greylist:" + hex.EncodeToString(sum[:16])

	value, found, err := p.store.Get(ctx, key)
	if err != nil {
		if p.logger != nil {
			p.logger.Warn("greylist store error; allowing message", "error", err)
		}
		return plugin.OK(), nil
	}
	if found {
		if value == "pass" {
			return plugin.OK(), nil
		}
		firstSeen, _ := strconv.ParseInt(value, 10, 64)
		if firstSeen > 0 && time.Since(time.Unix(firstSeen, 0)) >= p.delay {
			_ = p.store.Set(ctx, key, "pass", p.passTTL)
			tx.SetMeta("greylist.result", "passed")
			return plugin.OK(), nil
		}
		tx.SetMeta("greylist.result", "deferred")
		return plugin.TempFail(450, "4.7.1 Greylisted, please retry in %s", p.delay), nil
	}
	if err := p.store.Set(ctx, key, strconv.FormatInt(time.Now().Unix(), 10), p.passTTL); err != nil {
		return plugin.OK(), nil
	}
	tx.SetMeta("greylist.result", "new")
	return plugin.TempFail(450, "4.7.1 Greylisted, please retry in %s", p.delay), nil
}
