// Package headers adds trace, Message-ID, Date, Authentication-Results, and
// spam status headers at queue time.
package headers

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ferchd/gomta/plugin"
)

func init() {
	plugin.Register("headers", func(bc plugin.BuildContext, opts plugin.Options) (plugin.Plugin, error) {
		return &Plugin{
			addMessageID:   opts.Bool("add_message_id", true),
			addDate:        opts.Bool("add_date", true),
			addAuthResults: opts.Bool("add_auth_results", true),
			addSpamHeaders: opts.Bool("add_spam_headers", true),
			spamThreshold:  floatOption(opts, "spam_threshold", 5),
		}, nil
	})
}

// Plugin implements the headers hook.
type Plugin struct {
	addMessageID   bool
	addDate        bool
	addAuthResults bool
	addSpamHeaders bool
	spamThreshold  float64
}

// Name implements plugin.Plugin.
func (p *Plugin) Name() string { return "headers" }

// Hooks implements plugin.Plugin.
func (p *Plugin) Hooks() []plugin.Hook { return []plugin.Hook{plugin.HookQueue} }

// RunOrdered makes headers run before higher-priority body transformers such
// as dkim_sign, so signatures cover the added headers.
func (p *Plugin) RunOrdered() bool { return true }

// Run implements plugin.Plugin.
func (p *Plugin) Run(ctx context.Context, hook plugin.Hook, tx *plugin.Tx) (plugin.Outcome, error) {
	if len(tx.Data) == 0 {
		return plugin.OK(), nil
	}
	var headers []plugin.Header
	if p.addMessageID && !plugin.HasHeader(tx.Data, "Message-ID") {
		headers = append(headers, plugin.Header{
			Name:  "Message-ID",
			Value: fmt.Sprintf("<%s@%s>", tx.ID, tx.ServerName),
		})
	}
	if p.addDate && !plugin.HasHeader(tx.Data, "Date") {
		headers = append(headers, plugin.Header{Name: "Date", Value: time.Now().Format(time.RFC1123Z)})
	}
	if p.addAuthResults {
		if value := authResults(tx); value != "" {
			headers = append(headers, plugin.Header{Name: "Authentication-Results", Value: value})
		}
	}
	if p.addSpamHeaders {
		headers = append(headers, spamHeaders(tx, p.spamThreshold)...)
	}
	if len(headers) == 0 {
		return plugin.OK(), nil
	}
	body := plugin.PrependHeaders(tx.Data, headers)
	return plugin.Outcome{Action: plugin.ActionContinue, Body: body}, nil
}

func authResults(tx *plugin.Tx) string {
	var parts []string
	if result := tx.MetaString("spf.result"); result != "" && result != "none" {
		value := "spf=" + result
		if domain := tx.MetaString("spf.domain"); domain != "" {
			value += " smtp.mailfrom=" + domain
		}
		if exp := tx.MetaString("spf.explanation"); exp != "" && (result == "fail" || result == "softfail") {
			value += fmt.Sprintf(" reason=%q", plugin.SanitizeHeaderValue(exp))
		}
		parts = append(parts, value)
	}
	if result := tx.MetaString("dkim.result"); result != "" && result != "none" {
		value := "dkim=" + result
		if domain := tx.MetaString("dkim.domain"); domain != "" {
			value += " header.d=" + domain
		}
		parts = append(parts, value)
	}
	if result := tx.MetaString("dmarc.result"); result != "" && result != "none" {
		value := "dmarc=" + result
		if domain := tx.MetaString("dmarc.domain"); domain != "" {
			value += " header.from=" + domain
		}
		if policy := tx.MetaString("dmarc.policy"); policy != "" {
			value += " policy=" + policy
		}
		parts = append(parts, value)
	}
	if len(parts) == 0 {
		return ""
	}
	host := tx.ServerName
	if host == "" {
		host = "localhost"
	}
	return host + "; " + strings.Join(parts, "; ")
}

func spamHeaders(tx *plugin.Tx, threshold float64) []plugin.Header {
	score := 0.0
	var tests []string
	if raw := tx.MetaString("rspamd.score"); raw != "" {
		if v, err := strconv.ParseFloat(raw, 64); err == nil {
			score = v
		}
	}
	if action := tx.MetaString("rspamd.action"); action != "" {
		tests = append(tests, "RSPAMD_"+strings.ToUpper(strings.ReplaceAll(action, " ", "_")))
	}
	if symbols := tx.MetaString("rspamd.symbols"); symbols != "" {
		tests = append(tests, symbols)
	}
	switch tx.MetaString("spf.result") {
	case "fail":
		score += 3
		tests = append(tests, "SPF_FAIL")
	case "softfail":
		score += 2
		tests = append(tests, "SPF_SOFTFAIL")
	}
	if strings.EqualFold(tx.MetaString("dnsbl.listed"), "true") {
		score += 5
		tests = append(tests, "DNSBL")
	}
	if score == 0 && len(tests) == 0 {
		return nil
	}
	spam := score >= threshold || strings.EqualFold(tx.MetaString("rspamd.action"), "reject")
	status := fmt.Sprintf("%s, score=%.1f", yesNo(spam), score)
	if len(tests) > 0 {
		status += " tests=" + strings.Join(tests, ",")
	}
	out := []plugin.Header{
		{Name: "X-Spam-Status", Value: status},
		{Name: "X-Spam-Score", Value: strconv.FormatFloat(score, 'f', 1, 64)},
	}
	if spam {
		out = append(out, plugin.Header{Name: "X-Spam-Flag", Value: "YES"})
	}
	return out
}

func yesNo(v bool) string {
	if v {
		return "Yes"
	}
	return "No"
}

func floatOption(opts plugin.Options, key string, def float64) float64 {
	s := opts.String(key, "")
	if s == "" {
		return def
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return def
	}
	return v
}
