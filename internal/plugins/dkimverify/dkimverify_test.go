package dkimverify

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/ferchd/gomta/internal/dkimkey"
	"github.com/ferchd/gomta/plugin"
)

const testMessage = "From: Alice <alice@example.com>\r\n" +
	"To: Bob <bob@example.net>\r\n" +
	"Subject: hello\r\n" +
	"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
	"Message-ID: <abc@example.com>\r\n" +
	"\r\n" +
	"hello world\r\n"

func signedMessage(t *testing.T) (data []byte, txt string) {
	t.Helper()
	key, _, txt, err := dkimkey.GenerateRSA(1024)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := dkim.Sign(&buf, strings.NewReader(testMessage), &dkim.SignOptions{
		Domain:   "example.com",
		Selector: "sel",
		Signer:   key.Signer,
	}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), txt
}

func fakeLookup(t *testing.T, fn func(context.Context, string) ([]string, error)) {
	t.Helper()
	old := lookupTXT
	lookupTXT = fn
	t.Cleanup(func() { lookupTXT = old })
}

func newPlugin(t *testing.T, opts plugin.Options) *Plugin {
	t.Helper()
	p, err := plugin.New("dkim_verify", plugin.BuildContext{BaseDir: t.TempDir()}, opts)
	if err != nil {
		t.Fatal(err)
	}
	return p.(*Plugin)
}

func TestVerifyPass(t *testing.T) {
	data, txt := signedMessage(t)
	fakeLookup(t, func(context.Context, string) ([]string, error) {
		return []string{txt}, nil
	})
	p := newPlugin(t, nil)
	tx := plugin.NewTx()
	tx.Data = data
	out, err := p.Run(context.Background(), plugin.HookData, tx)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != plugin.ActionContinue {
		t.Fatalf("unexpected action %v", out.Action)
	}
	if tx.MetaString("dkim.result") != "pass" {
		t.Fatalf("unexpected result metadata: %+v", tx.MetaSnapshot())
	}
	if tx.MetaString("dkim.domain") != "example.com" || tx.MetaString("dkim.domains") != "example.com" {
		t.Fatalf("unexpected domain metadata: %+v", tx.MetaSnapshot())
	}
	if got := tx.MetaString("dkim.signatures"); got != "1" {
		t.Fatalf("unexpected signature count %q", got)
	}
}

func TestVerifyFail(t *testing.T) {
	data, txt := signedMessage(t)
	fakeLookup(t, func(context.Context, string) ([]string, error) {
		return []string{txt}, nil
	})
	tampered := append(append([]byte(nil), data...), []byte("tampered\r\n")...)
	p := newPlugin(t, nil)
	tx := plugin.NewTx()
	tx.Data = tampered
	out, err := p.Run(context.Background(), plugin.HookData, tx)
	if err != nil {
		t.Fatal(err)
	}
	if tx.MetaString("dkim.result") != "fail" {
		t.Fatalf("unexpected result metadata: %+v", tx.MetaSnapshot())
	}
	if out.Action != plugin.ActionContinue {
		t.Fatalf("unexpected action %v", out.Action)
	}

	strict := newPlugin(t, plugin.Options{"reject_fail": true})
	out, err = strict.Run(context.Background(), plugin.HookData, tx)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != plugin.ActionReject || out.Code != 550 {
		t.Fatalf("expected rejection, got %+v", out)
	}
}

func TestVerifyUnsigned(t *testing.T) {
	p := newPlugin(t, nil)
	tx := plugin.NewTx()
	tx.Data = []byte(testMessage)
	out, err := p.Run(context.Background(), plugin.HookData, tx)
	if err != nil {
		t.Fatal(err)
	}
	if tx.MetaString("dkim.result") != "none" {
		t.Fatalf("unexpected result metadata: %+v", tx.MetaSnapshot())
	}
	if out.Action != plugin.ActionContinue {
		t.Fatalf("unexpected action %v", out.Action)
	}

	strict := newPlugin(t, plugin.Options{"reject_unsigned": true})
	out, err = strict.Run(context.Background(), plugin.HookData, tx)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != plugin.ActionReject {
		t.Fatalf("expected rejection, got %+v", out)
	}
}

func TestVerifyTempError(t *testing.T) {
	data, _ := signedMessage(t)
	fakeLookup(t, func(_ context.Context, name string) ([]string, error) {
		return nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	})
	p := newPlugin(t, nil)
	tx := plugin.NewTx()
	tx.Data = data
	out, err := p.Run(context.Background(), plugin.HookData, tx)
	if err != nil {
		t.Fatal(err)
	}
	if tx.MetaString("dkim.result") != "temperror" {
		t.Fatalf("unexpected result metadata: %+v", tx.MetaSnapshot())
	}
	if out.Action != plugin.ActionContinue {
		t.Fatalf("unexpected action %v", out.Action)
	}

	strict := newPlugin(t, plugin.Options{"reject_temperror": true})
	out, err = strict.Run(context.Background(), plugin.HookData, tx)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != plugin.ActionTempFail || out.Code != 451 {
		t.Fatalf("expected tempfail, got %+v", out)
	}
}

func TestVerifyLookupErrorIsNotFatal(t *testing.T) {
	// A definitive verification error must not surface as a Go error; it is
	// reported through the transaction metadata.
	data, _ := signedMessage(t)
	fakeLookup(t, func(context.Context, string) ([]string, error) {
		return nil, errors.New("boom")
	})
	p := newPlugin(t, nil)
	tx := plugin.NewTx()
	tx.Data = data
	if _, err := p.Run(context.Background(), plugin.HookData, tx); err != nil {
		t.Fatal(err)
	}
	if got := tx.MetaString("dkim.result"); got != "temperror" && got != "fail" {
		t.Fatalf("unexpected result %q", got)
	}
}
