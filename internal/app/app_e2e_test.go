package app_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/ferchd/gomta/internal/app"
	"github.com/ferchd/gomta/internal/dkimkey"
	_ "github.com/ferchd/gomta/internal/plugins/all"
	"github.com/ferchd/gomta/internal/setup"
)

// patchConfig rewrites the generated config so listeners bind ephemeral ports
// and the status server stays off during the test.
func patchConfig(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	replacements := map[string]string{
		`address: ":2525"`:              `address: "127.0.0.1:0"`,
		`address: ":5587"`:              `address: "127.0.0.1:0"`,
		`address: "127.0.0.1:10025"`:    `address: "127.0.0.1:0"`,
		`status_addr: "127.0.0.1:8080"`: `status_addr: ""`,
	}
	for old, new := range replacements {
		if !strings.Contains(s, old) {
			t.Fatalf("generated config does not contain %q", old)
		}
		s = strings.ReplaceAll(s, old, new)
	}
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

// waitAddress waits until the named listener has bound a usable address.
func waitAddress(t *testing.T, a *app.App, name string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if addr := a.Server.Addresses()[name]; addr != "" && !strings.HasSuffix(addr, ":0") {
			conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				return addr
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("listener %q did not start", name)
	return ""
}

func waitForMail(t *testing.T, box string) []byte {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir(box)
		if err == nil && len(entries) > 0 {
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				data, err := os.ReadFile(filepath.Join(box, e.Name()))
				if err == nil {
					return data
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no message delivered to %s", box)
	return nil
}

func testMessage(from, to, subject, body string) []byte {
	return []byte("From: " + from + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
		"Message-ID: <e2e@example.com>\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" + body + "\r\n")
}

func TestEndToEndSubmissionAndMTA(t *testing.T) {
	dir := t.TempDir()
	res, err := setup.Init(setup.Options{
		Dir:           dir,
		Hostname:      "mail.example.com",
		Domains:       []string{"example.com"},
		AdminUser:     "postmaster@example.com",
		AdminPassword: "correct horse battery",
		KeyBits:       1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	patchConfig(t, res.ConfigPath)

	a, err := app.LoadWithOptions(res.ConfigPath, app.LoadOptions{LogLevel: "error"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("app.Run: %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Error("app did not stop in time")
		}
	})

	submission := waitAddress(t, a, "submission")
	mta := waitAddress(t, a, "smtp")

	// Submission: STARTTLS, authenticate, deliver locally. dkim_sign is
	// restricted to submission mode in the generated config.
	conn, err := net.Dial("tcp", submission)
	if err != nil {
		t.Fatal(err)
	}
	client, err := smtp.NewClientStartTLS(conn, &tls.Config{
		ServerName:         "mail.example.com",
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Hello("test.local"); err != nil {
		t.Fatal(err)
	}
	if err := client.Auth(sasl.NewPlainClient("", res.AdminUser, res.Password)); err != nil {
		t.Fatalf("auth: %v", err)
	}
	if err := client.Mail(res.AdminUser, nil); err != nil {
		t.Fatal(err)
	}
	if err := client.Rcpt(res.AdminUser, nil); err != nil {
		t.Fatal(err)
	}
	w, err := client.Data()
	if err != nil {
		t.Fatal(err)
	}
	submitted := testMessage("Alice <alice@example.com>", res.AdminUser, "e2e submission", "hello from submission")
	if _, err := w.Write(submitted); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Quit(); err != nil {
		t.Fatal(err)
	}

	box := filepath.Join(res.Dir, "mail", "example.com", "postmaster", "new")
	delivered := waitForMail(t, box)
	text := string(delivered)
	if !strings.Contains(text, "Subject: e2e submission") || !strings.Contains(text, "hello from submission") {
		t.Fatalf("delivered message lost content:\n%s", text)
	}
	if !strings.Contains(text, "Received:") || !strings.Contains(text, "with ESMTPSA") {
		t.Fatalf("missing or unexpected Received header:\n%s", text)
	}
	if !strings.Contains(text, "Delivered-To: postmaster@example.com") {
		t.Fatalf("missing Delivered-To header:\n%s", text)
	}
	if !strings.Contains(text, "DKIM-Signature:") {
		t.Fatalf("submission message was not DKIM signed:\n%s", text)
	}

	// The signature must verify against the generated key.
	keyPEM, err := os.ReadFile(res.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	key, err := dkimkey.ParsePEM(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	txt, err := dkimkey.DNSRecord(key)
	if err != nil {
		t.Fatal(err)
	}
	verifications, err := dkim.VerifyWithOptions(bytes.NewReader(delivered), &dkim.VerifyOptions{
		LookupTXT: func(string) ([]string, error) { return []string{txt}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(verifications) != 1 || verifications[0].Err != nil {
		t.Fatalf("delivered DKIM signature did not verify: %+v", verifications)
	}

	// MTA: plain SMTP, no auth, local recipient. The generated config only
	// signs submission traffic, so this message must not gain a signature.
	conn, err = net.Dial("tcp", mta)
	if err != nil {
		t.Fatal(err)
	}
	mtaClient := smtp.NewClient(conn)
	defer mtaClient.Close()
	if err := mtaClient.Hello("mta.test.local"); err != nil {
		t.Fatal(err)
	}
	if err := mtaClient.Mail("bob@example.com", nil); err != nil {
		t.Fatal(err)
	}
	if err := mtaClient.Rcpt("bob@example.com", nil); err != nil {
		t.Fatal(err)
	}
	w, err = mtaClient.Data()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(testMessage("Bob <bob@example.com>", "bob@example.com", "e2e mta", "hello from mta")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := mtaClient.Quit(); err != nil {
		t.Fatal(err)
	}

	bobBox := filepath.Join(res.Dir, "mail", "example.com", "bob", "new")
	bobText := string(waitForMail(t, bobBox))
	if !strings.Contains(bobText, "Subject: e2e mta") || !strings.Contains(bobText, "hello from mta") {
		t.Fatalf("MTA message lost content:\n%s", bobText)
	}
	if !strings.Contains(bobText, "with ESMTP") || strings.Contains(bobText, "with ESMTPSA") {
		t.Fatalf("unexpected Received header for unauthenticated MTA:\n%s", bobText)
	}
	if strings.Contains(bobText, "DKIM-Signature:") {
		t.Fatalf("MTA message should not be signed:\n%s", bobText)
	}
}
