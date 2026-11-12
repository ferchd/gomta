package rspamd

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ferchd/gomta/plugin"
)

func newPlugin(t *testing.T, opts plugin.Options) *Plugin {
	t.Helper()
	p, err := plugin.New("rspamd", plugin.BuildContext{BaseDir: t.TempDir()}, opts)
	if err != nil {
		t.Fatal(err)
	}
	return p.(*Plugin)
}

func scanServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestScanRejectAction(t *testing.T) {
	srv := scanServer(t, http.StatusOK, `{
		"score": 12.5,
		"action": "reject",
		"symbols": {"SPAM": {"name": "SPAM", "score": 10}, "B": {"name": "B", "score": 2.5}},
		"messages": {"SPAM": "looks like spam"}
	}`)
	p := newPlugin(t, plugin.Options{"url": srv.URL, "reject_action": true})
	tx := plugin.NewTx()
	tx.Data = []byte("Subject: test\r\n\r\nbody\r\n")
	out, err := p.Run(context.Background(), plugin.HookData, tx)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != plugin.ActionReject || out.Code != 550 {
		t.Fatalf("expected rejection, got %+v", out)
	}
	if tx.MetaString("rspamd.score") != "12.50" || tx.MetaString("rspamd.action") != "reject" {
		t.Fatalf("unexpected metadata: %+v", tx.MetaSnapshot())
	}
	if tx.MetaString("rspamd.symbols") != "B,SPAM" {
		t.Fatalf("unexpected symbols %q", tx.MetaString("rspamd.symbols"))
	}
	if tx.MetaString("rspamd.messages") != "SPAM: looks like spam" {
		t.Fatalf("unexpected messages %q", tx.MetaString("rspamd.messages"))
	}
}

func TestScanRejectActionDisabled(t *testing.T) {
	srv := scanServer(t, http.StatusOK, `{"score": 20, "action": "reject"}`)
	p := newPlugin(t, plugin.Options{"url": srv.URL})
	tx := plugin.NewTx()
	tx.Data = []byte("body")
	out, err := p.Run(context.Background(), plugin.HookData, tx)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != plugin.ActionContinue {
		t.Fatalf("expected continue, got %+v", out)
	}
	if len(out.Tags) != 1 || out.Tags[0] != "spam" {
		t.Fatalf("unexpected tags %v", out.Tags)
	}
}

func TestScanSoftRejectAndGreylist(t *testing.T) {
	tests := []struct {
		action string
		opt    string
		code   int
	}{
		{"soft reject", "reject_soft_reject", 451},
		{"greylist", "enforce_greylist", 450},
	}
	for _, tc := range tests {
		srv := scanServer(t, http.StatusOK, `{"score": 5, "action": "`+tc.action+`"}`)
		p := newPlugin(t, plugin.Options{"url": srv.URL, tc.opt: true})
		tx := plugin.NewTx()
		tx.Data = []byte("body")
		out, err := p.Run(context.Background(), plugin.HookData, tx)
		if err != nil {
			t.Fatal(err)
		}
		if out.Action != plugin.ActionTempFail || out.Code != tc.code {
			t.Errorf("%s: expected tempfail %d, got %+v", tc.action, tc.code, out)
		}
	}
}

func TestScanSendsHeaders(t *testing.T) {
	var seen *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Clone(context.Background())
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, `{"score": 0, "action": "no action"}`)
	}))
	defer srv.Close()

	p := newPlugin(t, plugin.Options{"url": srv.URL, "password": "secret", "skip_authenticated": false})
	tx := plugin.NewTx()
	tx.ID = "queue-1"
	tx.Data = []byte("body")
	tx.Helo = "helo.example"
	tx.MailFrom = "alice@example.com"
	tx.RcptTo = []string{"bob@example.net", "carol@example.net"}
	tx.RemoteIP = net.ParseIP("192.0.2.5")
	tx.AuthUser = "alice"
	tx.Mode = plugin.ModeSubmission
	if _, err := p.Run(context.Background(), plugin.HookData, tx); err != nil {
		t.Fatal(err)
	}
	if seen == nil {
		t.Fatal("rspamd was not called")
	}
	if got := seen.Header.Get("Queue-Id"); got != "queue-1" {
		t.Errorf("Queue-Id = %q", got)
	}
	if got := seen.Header.Get("Helo"); got != "helo.example" {
		t.Errorf("Helo = %q", got)
	}
	if got := seen.Header.Get("From"); got != "alice@example.com" {
		t.Errorf("From = %q", got)
	}
	if got := seen.Header.Values("Rcpt"); len(got) != 2 {
		t.Errorf("Rcpt = %v", got)
	}
	if got := seen.Header.Get("IP"); got != "192.0.2.5" {
		t.Errorf("IP = %q", got)
	}
	if got := seen.Header.Get("User"); got != "alice" {
		t.Errorf("User = %q", got)
	}
	if got := seen.Header.Get("Password"); got != "secret" {
		t.Errorf("Password = %q", got)
	}
	if got := seen.Header.Get("Protocol"); got != "submission" {
		t.Errorf("Protocol = %q", got)
	}
	if got := seen.Header.Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("Content-Type = %q", got)
	}
}

func TestScanSkipsAuthenticatedAndTrusted(t *testing.T) {
	p := newPlugin(t, plugin.Options{"url": "http://127.0.0.1:1"})
	tx := plugin.NewTx()
	tx.Data = []byte("body")
	tx.AuthUser = "alice"
	if _, err := p.Run(context.Background(), plugin.HookData, tx); err != nil {
		t.Fatal(err)
	}
	if tx.MetaString("rspamd.error") != "" {
		t.Fatalf("authenticated mail should not be scanned: %+v", tx.MetaSnapshot())
	}

	p = newPlugin(t, plugin.Options{"url": "http://127.0.0.1:1", "trusted_networks": []string{"10.0.0.0/8"}})
	tx = plugin.NewTx()
	tx.Data = []byte("body")
	tx.RemoteIP = net.ParseIP("10.1.2.3")
	if _, err := p.Run(context.Background(), plugin.HookData, tx); err != nil {
		t.Fatal(err)
	}
	if tx.MetaString("rspamd.error") != "" {
		t.Fatalf("trusted client should not be scanned: %+v", tx.MetaSnapshot())
	}
}

func TestScanError(t *testing.T) {
	srv := scanServer(t, http.StatusInternalServerError, "boom")
	p := newPlugin(t, plugin.Options{"url": srv.URL})
	tx := plugin.NewTx()
	tx.Data = []byte("body")
	out, err := p.Run(context.Background(), plugin.HookData, tx)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != plugin.ActionContinue {
		t.Fatalf("unexpected action %v", out.Action)
	}
	if tx.MetaString("rspamd.error") == "" {
		t.Fatal("expected rspamd.error metadata")
	}

	strict := newPlugin(t, plugin.Options{"url": srv.URL, "tempfail_on_error": true})
	out, err = strict.Run(context.Background(), plugin.HookData, tx)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != plugin.ActionTempFail || out.Code != 451 {
		t.Fatalf("expected tempfail, got %+v", out)
	}
}

func TestScanTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		io.WriteString(w, `{"score": 0, "action": "no action"}`)
	}))
	defer srv.Close()

	p := newPlugin(t, plugin.Options{"url": srv.URL, "timeout": "10ms"})
	tx := plugin.NewTx()
	tx.Data = []byte("body")
	if _, err := p.Run(context.Background(), plugin.HookData, tx); err != nil {
		t.Fatal(err)
	}
	if tx.MetaString("rspamd.error") == "" {
		t.Fatal("expected a timeout error")
	}
}

func TestFactoryValidation(t *testing.T) {
	if _, err := plugin.New("rspamd", plugin.BuildContext{BaseDir: t.TempDir()}, plugin.Options{
		"trusted_networks": []string{"not-a-network"},
	}); err == nil {
		t.Fatal("expected an error for an invalid trusted network")
	}
}
