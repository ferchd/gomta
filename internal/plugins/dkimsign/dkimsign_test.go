package dkimsign

import (
	"bytes"
	"context"
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
	"MIME-Version: 1.0\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\n" +
	"\r\n" +
	"hello world\r\n"

func newPlugin(t *testing.T, opts plugin.Options) *Plugin {
	t.Helper()
	if opts == nil {
		opts = plugin.Options{}
	}
	p, err := plugin.New("dkim_sign", plugin.BuildContext{BaseDir: t.TempDir()}, opts)
	if err != nil {
		t.Fatal(err)
	}
	return p.(*Plugin)
}

func TestSignProducesVerifiableSignature(t *testing.T) {
	_, pemStr, txt, err := dkimkey.GenerateRSA(1024)
	if err != nil {
		t.Fatal(err)
	}
	p := newPlugin(t, plugin.Options{
		"key":          pemStr,
		"domain":       "example.com",
		"selector":     "sel",
		"sign_domains": []string{"example.com"},
	})

	tx := plugin.NewTx()
	tx.Data = []byte(testMessage)
	tx.Mode = plugin.ModeSubmission
	out, err := p.Run(context.Background(), plugin.HookQueue, tx)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != plugin.ActionContinue {
		t.Fatalf("unexpected action %v", out.Action)
	}
	signed := string(out.Body)
	if !strings.Contains(signed, "DKIM-Signature:") {
		t.Fatalf("message was not signed:\n%s", signed)
	}
	if !strings.Contains(signed, "d=example.com") || !strings.Contains(signed, "s=sel") {
		t.Fatalf("signature tags missing:\n%s", signed)
	}
	if tx.MetaString("dkim.signed") != "true" || tx.MetaString("dkim.domain") != "example.com" {
		t.Fatalf("unexpected metadata: %+v", tx.MetaSnapshot())
	}

	verifications, err := dkim.VerifyWithOptions(bytes.NewReader(out.Body), &dkim.VerifyOptions{
		LookupTXT: func(string) ([]string, error) { return []string{txt}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(verifications) != 1 || verifications[0].Err != nil {
		t.Fatalf("signature did not verify: %+v", verifications)
	}
	if verifications[0].Domain != "example.com" {
		t.Fatalf("unexpected verified domain %q", verifications[0].Domain)
	}
}

func TestSignSkipsExistingSignature(t *testing.T) {
	_, pemStr, _, err := dkimkey.GenerateRSA(1024)
	if err != nil {
		t.Fatal(err)
	}
	p := newPlugin(t, plugin.Options{"key": pemStr, "domain": "example.com", "selector": "sel"})

	tx := plugin.NewTx()
	tx.Data = []byte(testMessage)
	first, err := p.Run(context.Background(), plugin.HookQueue, tx)
	if err != nil {
		t.Fatal(err)
	}
	tx.Data = first.Body

	second, err := p.Run(context.Background(), plugin.HookQueue, tx)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Body) != 0 {
		t.Fatal("already-signed message should not be signed again")
	}
	if got := strings.Count(string(tx.Data), "DKIM-Signature:"); got != 1 {
		t.Fatalf("expected one signature, found %d", got)
	}
	if tx.MetaString("dkim.signed") != "existing" {
		t.Fatalf("unexpected metadata: %+v", tx.MetaSnapshot())
	}
}

func TestSignSkipsDomainsOutsideSignList(t *testing.T) {
	_, pemStr, _, err := dkimkey.GenerateRSA(1024)
	if err != nil {
		t.Fatal(err)
	}
	p := newPlugin(t, plugin.Options{
		"key":          pemStr,
		"selector":     "sel",
		"sign_domains": []string{"other.example"},
	})
	tx := plugin.NewTx()
	tx.Data = []byte(testMessage)
	out, err := p.Run(context.Background(), plugin.HookQueue, tx)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Body) != 0 {
		t.Fatal("message from a non-signing domain was signed")
	}
	if _, ok := tx.Meta("dkim.signed"); ok {
		t.Fatal("unexpected dkim.signed metadata")
	}
}

func TestSignModes(t *testing.T) {
	_, pemStr, _, err := dkimkey.GenerateRSA(1024)
	if err != nil {
		t.Fatal(err)
	}
	p := newPlugin(t, plugin.Options{
		"key":      pemStr,
		"selector": "sel",
		"modes":    []string{"submission"},
	})
	tx := plugin.NewTx()
	tx.Data = []byte(testMessage)
	tx.Mode = plugin.ModeMTA
	out, err := p.Run(context.Background(), plugin.HookQueue, tx)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Body) != 0 {
		t.Fatal("signing ran outside its configured mode")
	}

	tx.Mode = plugin.ModeSubmission
	out, err = p.Run(context.Background(), plugin.HookQueue, tx)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Body) == 0 {
		t.Fatal("signing did not run in submission mode")
	}
}

func TestSignMissingFromDomain(t *testing.T) {
	_, pemStr, _, err := dkimkey.GenerateRSA(1024)
	if err != nil {
		t.Fatal(err)
	}
	p := newPlugin(t, plugin.Options{"key": pemStr, "selector": "sel"})
	tx := plugin.NewTx()
	tx.Data = []byte("Subject: no sender\r\n\r\nbody\r\n")
	if _, err := p.Run(context.Background(), plugin.HookQueue, tx); err == nil {
		t.Fatal("expected an error when the message has no From domain")
	}

	required := newPlugin(t, plugin.Options{"key": pemStr, "selector": "sel", "required": true})
	out, err := required.Run(context.Background(), plugin.HookQueue, tx)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != plugin.ActionTempFail {
		t.Fatalf("expected tempfail when signing is required, got %v", out.Action)
	}
}

func TestFactoryValidation(t *testing.T) {
	_, pemStr, _, err := dkimkey.GenerateRSA(1024)
	if err != nil {
		t.Fatal(err)
	}
	tests := []plugin.Options{
		{"selector": "sel"},                 // no key
		{"key": "bogus", "selector": "sel"}, // invalid PEM
		{"key": pemStr, "selector": "sel", "canonicalization": "bogus"},
		{"key": pemStr, "selector": "sel", "modes": []string{"bogus"}},
	}
	for i, opts := range tests {
		if _, err := plugin.New("dkim_sign", plugin.BuildContext{BaseDir: t.TempDir()}, opts); err == nil {
			t.Errorf("case %d: expected an error", i)
		}
	}
}

func TestParseCanonicalization(t *testing.T) {
	h, b, err := parseCanonicalization("relaxed/simple")
	if err != nil {
		t.Fatal(err)
	}
	if h != dkim.CanonicalizationRelaxed || b != dkim.CanonicalizationSimple {
		t.Fatalf("unexpected canonicalization: %v/%v", h, b)
	}
	h, b, err = parseCanonicalization("simple")
	if err != nil {
		t.Fatal(err)
	}
	if h != dkim.CanonicalizationSimple || b != dkim.CanonicalizationSimple {
		t.Fatalf("unexpected canonicalization: %v/%v", h, b)
	}
	if _, _, err := parseCanonicalization("a/b/c"); err == nil {
		t.Fatal("expected an error for too many parts")
	}
}

func TestSignatureTags(t *testing.T) {
	d, s := signatureTags("v=1; a=rsa-sha256; d=Example.com; s=sel; b=abc")
	if d != "Example.com" || s != "sel" {
		t.Fatalf("unexpected tags %q %q", d, s)
	}
}
