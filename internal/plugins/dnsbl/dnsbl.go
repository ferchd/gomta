// Package dnsbl checks the connecting IP against DNS blocklists.
package dnsbl

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/ferchd/gomta/plugin"
)

func init() {
	plugin.Register("dnsbl", func(bc plugin.BuildContext, opts plugin.Options) (plugin.Plugin, error) {
		p := &Plugin{
			zones:          opts.Strings("zones"),
			rejectListed:   opts.Bool("reject_listed", true),
			skipPrivate:    opts.Bool("skip_private", true),
			skipSubmission: opts.Bool("skip_submission", true),
			lookupTXT:      opts.Bool("lookup_txt", true),
		}
		if len(p.zones) == 0 {
			p.zones = []string{"zen.spamhaus.org"}
		}
		for _, raw := range opts.Strings("allowlist") {
			if ip := net.ParseIP(raw); ip != nil {
				bits := 128
				if ip.To4() != nil {
					bits = 32
				}
				p.allow = append(p.allow, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
				continue
			}
			_, n, err := net.ParseCIDR(raw)
			if err != nil {
				return nil, fmt.Errorf("allowlist: %w", err)
			}
			p.allow = append(p.allow, n)
		}
		return p, nil
	})
}

// Plugin implements the connect hook.
type Plugin struct {
	zones          []string
	rejectListed   bool
	skipPrivate    bool
	skipSubmission bool
	lookupTXT      bool
	allow          []*net.IPNet
}

func (p *Plugin) Name() string { return "dnsbl" }

func (p *Plugin) Hooks() []plugin.Hook { return []plugin.Hook{plugin.HookConnect} }

func (p *Plugin) Run(ctx context.Context, hook plugin.Hook, tx *plugin.Tx) (plugin.Outcome, error) {
	if p.skipSubmission && tx.Mode == plugin.ModeSubmission {
		return plugin.OK(), nil
	}
	ip := tx.RemoteIP
	if ip == nil || (p.skipPrivate && isPrivate(ip)) {
		return plugin.OK(), nil
	}
	for _, n := range p.allow {
		if n.Contains(ip) {
			return plugin.OK(), nil
		}
	}
	reverse := reverseIP(ip)
	type result struct {
		zone   string
		listed bool
		reason string
		err    error
	}
	results := make(chan result, len(p.zones))
	var wg sync.WaitGroup
	for _, zone := range p.zones {
		zone := strings.TrimSuffix(strings.TrimSpace(zone), ".")
		if zone == "" {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			query := reverse + "." + zone
			addrs, err := net.DefaultResolver.LookupHost(ctx, query)
			if err != nil {
				results <- result{zone: zone, err: err}
				return
			}
			if len(addrs) == 0 {
				results <- result{zone: zone}
				return
			}
			reason := ""
			if p.lookupTXT {
				if txts, err := net.DefaultResolver.LookupTXT(ctx, query); err == nil && len(txts) > 0 {
					reason = strings.Join(txts, " ")
				}
			}
			results <- result{zone: zone, listed: true, reason: reason}
		}()
	}
	wg.Wait()
	close(results)

	var listed []string
	var reasons []string
	var lookupErr error
	for r := range results {
		if r.listed {
			listed = append(listed, r.zone)
			if r.reason != "" {
				reasons = append(reasons, r.reason)
			}
		} else if r.err != nil && !isNotFound(r.err) {
			lookupErr = r.err
		}
	}
	tx.SetMeta("dnsbl.listed", len(listed) > 0)
	if len(listed) > 0 {
		tx.SetMeta("dnsbl.zones", strings.Join(listed, ","))
		if len(reasons) > 0 {
			tx.SetMeta("dnsbl.reason", strings.Join(reasons, "; "))
		}
		if p.rejectListed {
			return plugin.Reject(550, "5.7.1 Client host blocked by DNSBL %s", strings.Join(listed, ",")), nil
		}
		return plugin.OK(), nil
	}
	if lookupErr != nil {
		tx.SetMeta("dnsbl.error", lookupErr.Error())
	}
	return plugin.OK(), nil
}

func isPrivate(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified()
}

func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return err != nil && errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

func reverseIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0])
	}
	v6 := ip.To16()
	if v6 == nil {
		return ""
	}
	const hex = "0123456789abcdef"
	parts := make([]string, 0, 32)
	for i := len(v6) - 1; i >= 0; i-- {
		parts = append(parts, string(hex[v6[i]&0x0f]), string(hex[v6[i]>>4]))
	}
	return strings.Join(parts, ".")
}
