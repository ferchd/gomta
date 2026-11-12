// Package rspamd scans messages with an rspamd HTTP endpoint.
package rspamd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ferchd/gomta/plugin"
)

func init() {
	plugin.Register("rspamd", func(bc plugin.BuildContext, opts plugin.Options) (plugin.Plugin, error) {
		rawURL := opts.String("url", "http://127.0.0.1:11333")
		client := &http.Client{}
		endpoint := rawURL
		if strings.HasPrefix(rawURL, "unix://") {
			socket := strings.TrimPrefix(rawURL, "unix://")
			transport := &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socket)
				},
			}
			client.Transport = transport
			endpoint = "http://rspamd/checkv2"
		} else {
			endpoint = strings.TrimRight(rawURL, "/") + "/checkv2"
		}
		p := &Plugin{
			client:            client,
			endpoint:          endpoint,
			password:          opts.String("password", ""),
			skipAuthenticated: opts.Bool("skip_authenticated", true),
			rejectAction:      opts.Bool("reject_action", false),
			rejectSoft:        opts.Bool("reject_soft_reject", false),
			enforceGreylist:   opts.Bool("enforce_greylist", false),
			tempfailOnError:   opts.Bool("tempfail_on_error", false),
			timeout:           opts.Duration("timeout", 20*time.Second),
		}
		if p.timeout <= 0 {
			p.timeout = 20 * time.Second
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

// Plugin implements the data hook.
type Plugin struct {
	client            *http.Client
	endpoint          string
	password          string
	skipAuthenticated bool
	rejectAction      bool
	rejectSoft        bool
	enforceGreylist   bool
	tempfailOnError   bool
	timeout           time.Duration
	trusted           []*net.IPNet
}

// Name implements plugin.Plugin.
func (p *Plugin) Name() string { return "rspamd" }

// Hooks implements plugin.Plugin.
func (p *Plugin) Hooks() []plugin.Hook { return []plugin.Hook{plugin.HookData} }

// Run implements plugin.Plugin.
func (p *Plugin) Run(ctx context.Context, hook plugin.Hook, tx *plugin.Tx) (plugin.Outcome, error) {
	if len(tx.Data) == 0 {
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

	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(tx.Data))
	if err != nil {
		return p.failure(tx, err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Queue-Id", tx.ID)
	req.Header.Set("Helo", tx.Helo)
	req.Header.Set("From", tx.MailFrom)
	for _, rcpt := range tx.RcptTo {
		req.Header.Add("Rcpt", rcpt)
	}
	if tx.RemoteIP != nil {
		req.Header.Set("IP", tx.RemoteIP.String())
	}
	if tx.AuthUser != "" {
		req.Header.Set("User", tx.AuthUser)
	}
	if p.password != "" {
		req.Header.Set("Password", p.password)
	}
	if tx.Mode != "" {
		req.Header.Set("Protocol", string(tx.Mode))
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return p.failure(tx, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return p.failure(tx, err)
	}
	if resp.StatusCode != http.StatusOK {
		return p.failure(tx, fmt.Errorf("rspamd returned %s: %s", resp.Status, snippet(body)))
	}
	var result scanResult
	if err := json.Unmarshal(body, &result); err != nil {
		return p.failure(tx, fmt.Errorf("decode response: %w", err))
	}

	score := result.Score
	action := strings.ToLower(strings.TrimSpace(result.Action))
	tx.SetMeta("rspamd.score", strconv.FormatFloat(score, 'f', 2, 64))
	tx.SetMeta("rspamd.action", action)
	if symbols := symbolNames(result.Symbols); len(symbols) > 0 {
		tx.SetMeta("rspamd.symbols", strings.Join(symbols, ","))
	}
	if len(result.Messages) > 0 {
		names := make([]string, 0, len(result.Messages))
		for name := range result.Messages {
			names = append(names, name)
		}
		sort.Strings(names)
		var parts []string
		for _, name := range names {
			parts = append(parts, name+": "+result.Messages[name])
		}
		tx.SetMeta("rspamd.messages", strings.Join(parts, "; "))
	}

	switch action {
	case "reject":
		if p.rejectAction {
			return plugin.Reject(550, "5.7.1 Message rejected as spam (score %.2f)", score), nil
		}
		return plugin.Outcome{Action: plugin.ActionContinue, Tags: []string{"spam"}}, nil
	case "soft reject":
		if p.rejectSoft {
			return plugin.TempFail(451, "4.7.1 Message temporarily rejected (score %.2f)", score), nil
		}
	case "greylist":
		if p.enforceGreylist {
			return plugin.TempFail(450, "4.7.1 Greylisted, please retry later"), nil
		}
	}
	return plugin.OK(), nil
}

func (p *Plugin) failure(tx *plugin.Tx, err error) (plugin.Outcome, error) {
	tx.SetMeta("rspamd.error", err.Error())
	if p.tempfailOnError {
		return plugin.TempFail(451, "4.7.1 Spam filter temporarily unavailable"), nil
	}
	return plugin.OK(), nil
}

type scanResult struct {
	Score   float64 `json:"score"`
	Action  string  `json:"action"`
	Symbols map[string]struct {
		Name  string  `json:"name"`
		Score float64 `json:"score"`
	} `json:"symbols"`
	Messages map[string]string `json:"messages"`
}

func symbolNames(symbols map[string]struct {
	Name  string  `json:"name"`
	Score float64 `json:"score"`
}) []string {
	out := make([]string, 0, len(symbols))
	for name := range symbols {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}
