// Package dmarc applies DMARC policy to inbound messages.
package dmarc

import (
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"strings"

	"github.com/emersion/go-msgauth/dmarc"
	"github.com/ferchd/gomta/plugin"
	"golang.org/x/net/publicsuffix"
)

func init() {
	plugin.Register("dmarc", func(bc plugin.BuildContext, opts plugin.Options) (plugin.Plugin, error) {
		enforce := strings.ToLower(strings.TrimSpace(opts.String("enforce", "none")))
		switch enforce {
		case "none", "quarantine", "reject":
		default:
			return nil, fmt.Errorf("enforce must be none, quarantine or reject, got %q", enforce)
		}
		return &Plugin{
			enforce:            enforce,
			tempfailOnError:    opts.Bool("tempfail_on_error", false),
			skipAuthenticated:  opts.Bool("skip_authenticated", true),
			skipSubmission:     opts.Bool("skip_submission", true),
			quarantineAsReject: opts.Bool("quarantine_as_reject", false),
		}, nil
	})
}

// Plugin implements the data hook as an ordered plugin so DKIM results are
// available.
type Plugin struct {
	enforce            string
	tempfailOnError    bool
	skipAuthenticated  bool
	skipSubmission     bool
	quarantineAsReject bool
}

// Name implements plugin.Plugin.
func (p *Plugin) Name() string { return "dmarc" }

// Hooks implements plugin.Plugin.
func (p *Plugin) Hooks() []plugin.Hook { return []plugin.Hook{plugin.HookData} }

// RunOrdered makes DMARC run after DKIM verification.
func (p *Plugin) RunOrdered() bool { return true }

// Run implements plugin.Plugin.
func (p *Plugin) Run(ctx context.Context, hook plugin.Hook, tx *plugin.Tx) (plugin.Outcome, error) {
	if len(tx.Data) == 0 {
		return plugin.OK(), nil
	}
	if p.skipAuthenticated && tx.AuthUser != "" {
		return plugin.OK(), nil
	}
	if p.skipSubmission && tx.Mode == plugin.ModeSubmission {
		return plugin.OK(), nil
	}
	from := plugin.FromDomain(tx.Data)
	if from == "" {
		return plugin.OK(), nil
	}

	record, recordDomain, err := lookup(ctx, from)
	if err == dmarc.ErrNoPolicy {
		tx.SetMeta("dmarc.result", "none")
		tx.SetMeta("dmarc.domain", from)
		return plugin.OK(), nil
	}
	if err != nil {
		tx.SetMeta("dmarc.result", "temperror")
		tx.SetMeta("dmarc.domain", from)
		tx.SetMeta("dmarc.error", err.Error())
		if p.tempfailOnError {
			return plugin.TempFail(451, "4.7.1 DMARC lookup failed for %s", from), nil
		}
		return plugin.OK(), nil
	}

	spfAligned := p.spfAligned(from, record.SPFAlignment, tx)
	dkimAligned := p.dkimAligned(from, record.DKIMAlignment, tx)
	result := "fail"
	if spfAligned || dkimAligned {
		result = "pass"
	}

	policy := record.Policy
	if !strings.EqualFold(recordDomain, from) && record.SubdomainPolicy != "" {
		policy = record.SubdomainPolicy
	}
	tx.SetMeta("dmarc.result", result)
	tx.SetMeta("dmarc.domain", from)
	tx.SetMeta("dmarc.record_domain", recordDomain)
	tx.SetMeta("dmarc.policy", string(policy))
	tx.SetMeta("dmarc.spf_aligned", spfAligned)
	tx.SetMeta("dmarc.dkim_aligned", dkimAligned)

	if result == "pass" {
		return plugin.Outcome{Action: plugin.ActionContinue, Tags: []string{"dmarc-pass"}}, nil
	}
	if !p.shouldEnforce(tx, record) {
		return plugin.OK(), nil
	}

	switch effective(policy, p.enforce) {
	case dmarc.PolicyReject:
		return plugin.Reject(550, "5.7.1 DMARC policy rejected message from %s", from), nil
	case dmarc.PolicyQuarantine:
		if p.quarantineAsReject {
			return plugin.Reject(550, "5.7.1 DMARC policy rejected message from %s", from), nil
		}
		return plugin.Outcome{
			Action:  plugin.ActionQuarantine,
			Message: fmt.Sprintf("DMARC policy quarantined message from %s", from),
		}, nil
	default:
		return plugin.OK(), nil
	}
}

func (p *Plugin) spfAligned(from string, mode dmarc.AlignmentMode, tx *plugin.Tx) bool {
	result := strings.ToLower(tx.MetaString("spf.result"))
	if result != "pass" {
		return false
	}
	return aligned(from, tx.MetaString("spf.domain"), mode)
}

func (p *Plugin) dkimAligned(from string, mode dmarc.AlignmentMode, tx *plugin.Tx) bool {
	if strings.ToLower(tx.MetaString("dkim.result")) != "pass" {
		return false
	}
	raw := tx.MetaString("dkim.domains")
	if raw == "" {
		raw = tx.MetaString("dkim.domain")
	}
	for _, domain := range strings.Split(raw, ",") {
		if aligned(from, domain, mode) {
			return true
		}
	}
	return false
}

// shouldEnforce honors the DMARC pct parameter. Sampling is deterministic per
// queue ID so retries apply the same decision.
func (p *Plugin) shouldEnforce(tx *plugin.Tx, record *dmarc.Record) bool {
	if p.enforce == "none" {
		return false
	}
	if record.Percent != nil {
		pct := *record.Percent
		if pct <= 0 {
			return false
		}
		if pct < 100 {
			h := fnv.New32a()
			_, _ = h.Write([]byte(tx.ID))
			if int(h.Sum32()%100) >= pct {
				return false
			}
		}
	}
	return true
}

// dnsLookup is indirected so tests can supply deterministic DNS data.
var dnsLookup = func(ctx context.Context, name string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, name)
}

func lookup(ctx context.Context, domain string) (*dmarc.Record, string, error) {
	lookupTXT := func(name string) ([]string, error) {
		return dnsLookup(ctx, name)
	}
	record, err := dmarc.LookupWithOptions(domain, &dmarc.LookupOptions{LookupTXT: lookupTXT})
	if err == nil {
		return record, domain, nil
	}
	if err != dmarc.ErrNoPolicy {
		return nil, "", err
	}
	org := organizationalDomain(domain)
	if org == "" || org == domain {
		return nil, domain, dmarc.ErrNoPolicy
	}
	record, err = dmarc.LookupWithOptions(org, &dmarc.LookupOptions{LookupTXT: lookupTXT})
	if err != nil {
		return nil, org, err
	}
	return record, org, nil
}

func aligned(from, candidate string, mode dmarc.AlignmentMode) bool {
	candidate = strings.ToLower(strings.TrimSpace(candidate))
	from = strings.ToLower(strings.TrimSpace(from))
	if candidate == "" || from == "" {
		return false
	}
	if candidate == from {
		return true
	}
	if mode == dmarc.AlignmentStrict {
		return false
	}
	return organizationalDomain(candidate) == organizationalDomain(from)
}

func organizationalDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" {
		return ""
	}
	if org, err := publicsuffix.EffectiveTLDPlusOne(domain); err == nil {
		return org
	}
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return domain
}

func effective(published dmarc.Policy, enforce string) dmarc.Policy {
	rank := func(p dmarc.Policy) int {
		switch p {
		case dmarc.PolicyReject:
			return 2
		case dmarc.PolicyQuarantine:
			return 1
		default:
			return 0
		}
	}
	pub := published
	if rank(pub) > rank(dmarc.Policy(enforce)) {
		return dmarc.Policy(enforce)
	}
	return pub
}
