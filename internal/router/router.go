// Package router maps envelope recipients to local, filter, or outbound
// delivery backends.
package router

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/ferchd/gomta/config"
	"github.com/ferchd/gomta/delivery"
	"github.com/ferchd/gomta/plugin"
	"github.com/ferchd/gomta/queue"
)

// Router implements queue.Router.
type Router struct {
	domains  *config.Domains
	local    delivery.Backend
	outbound delivery.Backend
	filter   delivery.Backend
}

// New builds all configured delivery backends.
func New(cfg *config.Config, domains *config.Domains, bc plugin.BuildContext) (*Router, error) {
	local, err := delivery.New(cfg.Routing.LocalBackend, bc, plugin.Options(cfg.Routing.LocalOptions))
	if err != nil {
		return nil, fmt.Errorf("local backend: %w", err)
	}
	outbound, err := delivery.New(cfg.Routing.OutboundBackend, bc, plugin.Options(cfg.Routing.OutboundOptions))
	if err != nil {
		return nil, fmt.Errorf("outbound backend: %w", err)
	}
	r := &Router{domains: domains, local: local, outbound: outbound}
	if strings.TrimSpace(cfg.Routing.FilterUpstream) != "" {
		filter, err := buildFilter(cfg.Routing.FilterUpstream, cfg.Routing.FilterOptions, bc)
		if err != nil {
			return nil, fmt.Errorf("filter upstream: %w", err)
		}
		r.filter = filter
	}
	return r, nil
}

func buildFilter(raw string, opts map[string]any, bc plugin.BuildContext) (delivery.Backend, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" {
		u, err = url.Parse("smtp://" + raw)
		if err != nil {
			return nil, err
		}
	}
	merged := plugin.Options{}
	for k, v := range opts {
		merged[k] = v
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		merged["url"] = u.String()
		return delivery.New("http", bc, merged)
	case "smtp", "smtps", "lmtp":
		host := u.Host
		if u.Port() == "" {
			switch u.Scheme {
			case "lmtp":
				host = u.Hostname() + ":24"
			case "smtps":
				host = u.Hostname() + ":465"
			default:
				host = u.Hostname() + ":25"
			}
		}
		if u.User != nil {
			merged["username"] = u.User.Username()
			if pass, ok := u.User.Password(); ok {
				merged["password"] = pass
			}
		}
		if u.Scheme == "smtps" {
			merged["tls"] = "implicit"
			merged["smarthost"] = host
			return delivery.New("smtp", bc, merged)
		}
		if u.Scheme == "lmtp" {
			merged["host"] = host
			return delivery.New("lmtp", bc, merged)
		}
		merged["smarthost"] = host
		return delivery.New("smtp", bc, merged)
	default:
		return nil, fmt.Errorf("unsupported scheme %q (use smtp, smtps, lmtp, http or https)", u.Scheme)
	}
}

// Route selects a backend for rcpt.
func (r *Router) Route(env *queue.Envelope, rcpt string) (queue.Route, error) {
	domain := plugin.Domain(rcpt)
	if domain == "" {
		return queue.Route{}, fmt.Errorf("invalid recipient %q", rcpt)
	}
	if r.domains.IsLocal(domain) {
		if env.Mode == string(plugin.ModeFilter) && r.filter != nil {
			return queue.Route{Key: "filter", Backend: r.filter}, nil
		}
		return queue.Route{Key: "local", Backend: r.local}, nil
	}
	if env.Mode == string(plugin.ModeFilter) {
		return queue.Route{}, fmt.Errorf("domain %s is not local", domain)
	}
	if r.outbound.Name() == "smtp" {
		return queue.Route{Key: "mx:" + domain, Backend: r.outbound}, nil
	}
	return queue.Route{Key: "outbound", Backend: r.outbound}, nil
}

// Backends returns backend names for diagnostics.
func (r *Router) Backends() (local, outbound, filter string) {
	local, outbound = r.local.Name(), r.outbound.Name()
	if r.filter != nil {
		filter = r.filter.Name()
	}
	return
}
