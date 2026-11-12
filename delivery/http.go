package delivery

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ferchd/gomta/plugin"
)

func init() {
	Register("http", NewHTTP)
}

// NewHTTP constructs an HTTP webhook delivery backend. The backend POSTs a
// JSON envelope with the message base64-encoded and expects a 2xx response.
func NewHTTP(bc plugin.BuildContext, opts plugin.Options) (Backend, error) {
	url := opts.String("url", "")
	if url == "" {
		return nil, fmt.Errorf("url is required")
	}
	headers := map[string]string{}
	for k, v := range opts.Map("headers") {
		headers[k] = fmt.Sprint(v)
	}
	return &httpBackend{
		url:     url,
		token:   opts.String("token", ""),
		headers: headers,
		client:  &http.Client{Timeout: opts.Duration("timeout", 30*time.Second)},
	}, nil
}

type httpBackend struct {
	url     string
	token   string
	headers map[string]string
	client  *http.Client
}

func (b *httpBackend) Name() string { return "http" }

type httpRequest struct {
	ID       string            `json:"id"`
	From     string            `json:"from"`
	To       []string          `json:"to"`
	Mode     string            `json:"mode,omitempty"`
	Helo     string            `json:"helo,omitempty"`
	RemoteIP string            `json:"remote_ip,omitempty"`
	Meta     map[string]string `json:"meta,omitempty"`
	Message  string            `json:"message_base64"`
}

func (b *httpBackend) Deliver(ctx context.Context, m *Message) map[string]error {
	results := make(map[string]error, len(m.To))
	payload, err := json.Marshal(httpRequest{
		ID:       m.ID,
		From:     m.From,
		To:       m.To,
		Mode:     m.Mode,
		Helo:     m.Helo,
		RemoteIP: m.RemoteIP,
		Meta:     m.Meta,
		Message:  base64.StdEncoding.EncodeToString(m.Data),
	})
	if err != nil {
		for _, rcpt := range m.To {
			results[rcpt] = Perm(err)
		}
		return results
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.url, bytes.NewReader(payload))
	if err != nil {
		for _, rcpt := range m.To {
			results[rcpt] = Perm(err)
		}
		return results
	}
	req.Header.Set("Content-Type", "application/json")
	if b.token != "" {
		req.Header.Set("Authorization", "Bearer "+b.token)
	}
	for k, v := range b.headers {
		req.Header.Set(k, v)
	}
	resp, err := b.client.Do(req)
	if err != nil {
		e := Temp(err)
		for _, rcpt := range m.To {
			results[rcpt] = e
		}
		return results
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		for _, rcpt := range m.To {
			results[rcpt] = nil
		}
		return results
	}
	var e error
	msg := strings.TrimSpace(string(body))
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		e = Perm(fmt.Errorf("webhook returned %d: %s", resp.StatusCode, msg))
	} else {
		e = Temp(fmt.Errorf("webhook returned %d: %s", resp.StatusCode, msg))
	}
	for _, rcpt := range m.To {
		results[rcpt] = e
	}
	return results
}
