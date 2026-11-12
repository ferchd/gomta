// Package dkimsign signs outgoing messages with DKIM at queue time.
package dkimsign

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/ferchd/gomta/internal/dkimkey"
	"github.com/ferchd/gomta/plugin"
)

// DefaultHeaders is the RFC 6376 recommended header set plus common MIME fields.
var DefaultHeaders = []string{
	"From", "To", "Cc", "Reply-To", "Subject", "Date", "Message-ID",
	"MIME-Version", "Content-Type", "Content-Transfer-Encoding",
	"List-Unsubscribe", "In-Reply-To", "References",
}

func init() {
	plugin.Register("dkim_sign", func(bc plugin.BuildContext, opts plugin.Options) (plugin.Plugin, error) {
		var raw []byte
		if key := opts.String("key", ""); key != "" {
			raw = []byte(key)
		} else {
			path := bc.Path(opts.String("key_file", ""))
			if path == "" {
				return nil, fmt.Errorf("key_file (or inline key) is required")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("read key_file: %w", err)
			}
			raw = data
		}
		key, err := dkimkey.ParsePEM(raw)
		if err != nil {
			return nil, err
		}
		if key.Algo == "rsa" && key.Bits < 1024 {
			return nil, fmt.Errorf("RSA key is too small (%d bits, minimum 1024)", key.Bits)
		}
		headerCanon, bodyCanon, err := parseCanonicalization(opts.String("canonicalization", "relaxed/relaxed"))
		if err != nil {
			return nil, err
		}
		p := &Plugin{
			key:         key,
			domain:      strings.ToLower(strings.TrimSpace(opts.String("domain", ""))),
			selector:    strings.TrimSpace(opts.String("selector", "default")),
			headers:     opts.Strings("headers"),
			headerCanon: headerCanon,
			bodyCanon:   bodyCanon,
			expire:      opts.Duration("expire", 0),
			skipSigned:  opts.Bool("skip_signed", true),
			required:    opts.Bool("required", false),
		}
		if len(p.headers) == 0 {
			p.headers = append([]string(nil), DefaultHeaders...)
		}
		if len(p.headers) == 0 {
			return nil, fmt.Errorf("headers must not be empty")
		}
		for _, d := range opts.Strings("sign_domains") {
			d = strings.ToLower(strings.TrimSpace(d))
			if d != "" {
				p.domains = append(p.domains, d)
			}
		}
		for _, m := range opts.Strings("modes") {
			m = strings.ToLower(strings.TrimSpace(m))
			if !plugin.Mode(m).Valid() {
				return nil, fmt.Errorf("modes: unknown mode %q", m)
			}
			p.modes = append(p.modes, plugin.Mode(m))
		}
		if p.selector == "" {
			return nil, fmt.Errorf("selector is required")
		}
		return p, nil
	})
}

// Plugin implements the queue hook.
type Plugin struct {
	key         *dkimkey.Key
	domain      string
	selector    string
	headers     []string
	headerCanon dkim.Canonicalization
	bodyCanon   dkim.Canonicalization
	expire      time.Duration
	skipSigned  bool
	required    bool
	domains     []string
	modes       []plugin.Mode
}

// Name implements plugin.Plugin.
func (p *Plugin) Name() string { return "dkim_sign" }

// Hooks implements plugin.Plugin.
func (p *Plugin) Hooks() []plugin.Hook { return []plugin.Hook{plugin.HookQueue} }

// RunOrdered makes signing run after header-generating plugins.
func (p *Plugin) RunOrdered() bool { return true }

// Run implements plugin.Plugin.
func (p *Plugin) Run(ctx context.Context, hook plugin.Hook, tx *plugin.Tx) (plugin.Outcome, error) {
	if len(tx.Data) == 0 {
		return plugin.OK(), nil
	}
	if len(p.modes) > 0 {
		ok := false
		for _, m := range p.modes {
			if tx.Mode == m {
				ok = true
				break
			}
		}
		if !ok {
			return plugin.OK(), nil
		}
	}
	domain := p.domain
	if domain == "" {
		domain = plugin.FromDomain(tx.Data)
	}
	if domain == "" {
		return p.fail("message has no usable From domain")
	}
	if len(p.domains) > 0 {
		matched := false
		for _, d := range p.domains {
			if strings.EqualFold(d, domain) {
				matched = true
				break
			}
		}
		if !matched {
			return plugin.OK(), nil
		}
	}
	if p.skipSigned && hasSignature(tx.Data, domain, p.selector) {
		tx.SetMeta("dkim.signed", "existing")
		return plugin.OK(), nil
	}

	options := &dkim.SignOptions{
		Domain:                 domain,
		Selector:               p.selector,
		Signer:                 p.key.Signer,
		Hash:                   crypto.SHA256,
		HeaderCanonicalization: p.headerCanon,
		BodyCanonicalization:   p.bodyCanon,
		HeaderKeys:             p.headers,
	}
	if p.expire > 0 {
		options.Expiration = time.Now().Add(p.expire)
	}

	var buf bytes.Buffer
	if err := dkim.Sign(&buf, bytes.NewReader(tx.Data), options); err != nil {
		return p.fail(fmt.Sprintf("sign: %v", err))
	}
	tx.SetMeta("dkim.signed", "true")
	tx.SetMeta("dkim.domain", domain)
	tx.SetMeta("dkim.selector", p.selector)
	return plugin.Outcome{
		Action: plugin.ActionContinue,
		Body:   buf.Bytes(),
		Meta: map[string]any{
			"dkim.signed":   "true",
			"dkim.domain":   domain,
			"dkim.selector": p.selector,
		},
	}, nil
}

func (p *Plugin) fail(reason string) (plugin.Outcome, error) {
	if p.required {
		return plugin.TempFail(451, "4.3.0 Unable to sign message: %s", reason), nil
	}
	return plugin.OK(), fmt.Errorf("dkim_sign: %s", reason)
}

func parseCanonicalization(v string) (dkim.Canonicalization, dkim.Canonicalization, error) {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(v)), "/")
	parse := func(s string) (dkim.Canonicalization, error) {
		switch s {
		case "", "simple":
			return dkim.CanonicalizationSimple, nil
		case "relaxed":
			return dkim.CanonicalizationRelaxed, nil
		default:
			return "", fmt.Errorf("canonicalization must be simple or relaxed, got %q", s)
		}
	}
	h, err := parse(parts[0])
	if err != nil {
		return "", "", err
	}
	body := h
	if len(parts) > 1 {
		body, err = parse(parts[1])
		if err != nil {
			return "", "", err
		}
	}
	if len(parts) > 2 {
		return "", "", fmt.Errorf("canonicalization must be header/body")
	}
	return h, body, nil
}

func hasSignature(data []byte, domain, selector string) bool {
	headers := plugin.ParseHeaders(data)
	for _, value := range headers["dkim-signature"] {
		d, s := signatureTags(value)
		if strings.EqualFold(d, domain) && strings.EqualFold(s, selector) {
			return true
		}
	}
	return false
}

func signatureTags(value string) (domain, selector string) {
	for _, part := range strings.Split(value, ";") {
		part = strings.TrimSpace(part)
		key, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "d":
			domain = strings.TrimSpace(val)
		case "s":
			selector = strings.TrimSpace(val)
		}
	}
	return
}
