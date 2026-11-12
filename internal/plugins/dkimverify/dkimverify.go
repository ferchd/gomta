// Package dkimverify verifies DKIM signatures on inbound messages.
package dkimverify

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/ferchd/gomta/plugin"
)

func init() {
	plugin.Register("dkim_verify", func(bc plugin.BuildContext, opts plugin.Options) (plugin.Plugin, error) {
		return &Plugin{
			maxVerifications: opts.Int("max_verifications", 10),
			rejectFail:       opts.Bool("reject_fail", false),
			rejectUnsigned:   opts.Bool("reject_unsigned", false),
			rejectTempfail:   opts.Bool("reject_temperror", false),
		}, nil
	})
}

// lookupTXT matches the DNS surface used by go-msgauth. Tests can replace it.
var lookupTXT = func(ctx context.Context, domain string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, domain)
}

// Plugin implements the data hook.
type Plugin struct {
	maxVerifications int
	rejectFail       bool
	rejectUnsigned   bool
	rejectTempfail   bool
}

// Name implements plugin.Plugin.
func (p *Plugin) Name() string { return "dkim_verify" }

// Hooks implements plugin.Plugin.
func (p *Plugin) Hooks() []plugin.Hook { return []plugin.Hook{plugin.HookData} }

// Run implements plugin.Plugin.
func (p *Plugin) Run(ctx context.Context, hook plugin.Hook, tx *plugin.Tx) (plugin.Outcome, error) {
	if len(tx.Data) == 0 {
		return plugin.OK(), nil
	}
	options := &dkim.VerifyOptions{
		LookupTXT: func(domain string) ([]string, error) {
			return lookupTXT(ctx, domain)
		},
		MaxVerifications: p.maxVerifications,
	}
	verifications, err := dkim.VerifyWithOptions(bytes.NewReader(tx.Data), options)
	if err != nil && err != dkim.ErrTooManySignatures {
		tx.SetMeta("dkim.result", "temperror")
		return p.tempfail(fmt.Sprintf("verification failed: %v", err)), nil
	}

	result := "none"
	domain := ""
	identity := ""
	valid := 0
	temp := false
	var validDomains []string
	for _, v := range verifications {
		if domain == "" {
			domain = v.Domain
			identity = v.Identifier
		}
		if v.Err == nil {
			valid++
			result = "pass"
			validDomains = append(validDomains, strings.ToLower(v.Domain))
			if len(validDomains) == 1 {
				domain = v.Domain
				identity = v.Identifier
			}
			continue
		}
		if dkim.IsTempFail(v.Err) {
			temp = true
		}
	}
	if result != "pass" && len(verifications) > 0 && temp {
		result = "temperror"
	} else if result != "pass" && len(verifications) > 0 {
		result = "fail"
	}

	tx.SetMeta("dkim.result", result)
	tx.SetMeta("dkim.signatures", len(verifications))
	tx.SetMeta("dkim.valid", valid)
	if domain != "" {
		tx.SetMeta("dkim.domain", strings.ToLower(domain))
	}
	if identity != "" {
		tx.SetMeta("dkim.identity", identity)
	}
	if len(validDomains) > 0 {
		tx.SetMeta("dkim.domains", strings.Join(validDomains, ","))
	}
	if result == "pass" {
		return plugin.Outcome{Action: plugin.ActionContinue, Tags: []string{"dkim-verified"}}, nil
	}
	switch result {
	case "fail":
		if p.rejectFail {
			return p.reject("5.7.1 DKIM signature verification failed"), nil
		}
	case "temperror":
		if p.rejectTempfail {
			return p.tempfail("4.7.1 DKIM verification temporarily failed"), nil
		}
	}
	if len(verifications) == 0 && p.rejectUnsigned {
		return p.reject("5.7.1 Message is not DKIM signed"), nil
	}
	return plugin.OK(), nil
}

func (p *Plugin) reject(msg string) plugin.Outcome {
	return plugin.Reject(550, "%s", msg)
}

func (p *Plugin) tempfail(msg string) plugin.Outcome {
	return plugin.TempFail(451, "%s", msg)
}
