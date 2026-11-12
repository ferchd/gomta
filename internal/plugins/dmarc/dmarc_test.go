package dmarc

import (
	"context"
	"net"
	"testing"

	"github.com/emersion/go-msgauth/dmarc"
	"github.com/ferchd/gomta/plugin"
)

func setDNS(t *testing.T, records map[string]string) {
	t.Helper()
	old := dnsLookup
	dnsLookup = func(_ context.Context, name string) ([]string, error) {
		if txt, ok := records[name]; ok {
			return []string{txt}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	t.Cleanup(func() { dnsLookup = old })
}

func message(from string) []byte {
	return []byte("From: " + from + "\r\nTo: bob@example.net\r\nSubject: test\r\n\r\nbody\r\n")
}

func newPlugin(t *testing.T, opts plugin.Options) *Plugin {
	t.Helper()
	p, err := plugin.New("dmarc", plugin.BuildContext{BaseDir: t.TempDir()}, opts)
	if err != nil {
		t.Fatal(err)
	}
	return p.(*Plugin)
}

func run(t *testing.T, p *Plugin, from string, setup func(*plugin.Tx)) (*plugin.Tx, plugin.Outcome) {
	t.Helper()
	tx := plugin.NewTx()
	tx.Data = message(from)
	if setup != nil {
		setup(tx)
	}
	out, err := p.Run(context.Background(), plugin.HookData, tx)
	if err != nil {
		t.Fatal(err)
	}
	return tx, out
}

func TestNoPolicy(t *testing.T) {
	setDNS(t, nil)
	p := newPlugin(t, nil)
	tx, out := run(t, p, "alice@example.com", nil)
	if out.Action != plugin.ActionContinue {
		t.Fatalf("unexpected action %v", out.Action)
	}
	if tx.MetaString("dmarc.result") != "none" {
		t.Fatalf("unexpected metadata: %+v", tx.MetaSnapshot())
	}
}

func TestPolicyNoneAnnotatesOnly(t *testing.T) {
	setDNS(t, map[string]string{
		"_dmarc.example.com": "v=DMARC1; p=none",
	})
	p := newPlugin(t, nil)
	tx, out := run(t, p, "alice@example.com", nil)
	if out.Action != plugin.ActionContinue {
		t.Fatalf("unexpected action %v", out.Action)
	}
	if tx.MetaString("dmarc.result") != "fail" {
		t.Fatalf("unexpected result: %+v", tx.MetaSnapshot())
	}
	if tx.MetaString("dmarc.policy") != "none" {
		t.Fatalf("unexpected policy: %+v", tx.MetaSnapshot())
	}
}

func TestEnforceReject(t *testing.T) {
	setDNS(t, map[string]string{
		"_dmarc.example.com": "v=DMARC1; p=reject",
	})
	p := newPlugin(t, plugin.Options{"enforce": "reject"})
	_, out := run(t, p, "alice@example.com", nil)
	if out.Action != plugin.ActionReject || out.Code != 550 {
		t.Fatalf("expected rejection, got %+v", out)
	}
}

func TestEnforceQuarantine(t *testing.T) {
	setDNS(t, map[string]string{
		"_dmarc.example.com": "v=DMARC1; p=quarantine",
	})
	p := newPlugin(t, plugin.Options{"enforce": "quarantine"})
	_, out := run(t, p, "alice@example.com", nil)
	if out.Action != plugin.ActionQuarantine {
		t.Fatalf("expected quarantine, got %+v", out)
	}

	rejecting := newPlugin(t, plugin.Options{"enforce": "quarantine", "quarantine_as_reject": true})
	_, out = run(t, rejecting, "alice@example.com", nil)
	if out.Action != plugin.ActionReject {
		t.Fatalf("expected quarantine-as-reject, got %+v", out)
	}
}

func TestSPFAlignmentRelaxed(t *testing.T) {
	setDNS(t, map[string]string{
		"_dmarc.example.com": "v=DMARC1; p=reject",
	})
	p := newPlugin(t, plugin.Options{"enforce": "reject"})
	tx, out := run(t, p, "alice@sub.example.com", func(tx *plugin.Tx) {
		tx.SetMeta("spf.result", "pass")
		tx.SetMeta("spf.domain", "mail.example.com")
	})
	if out.Action != plugin.ActionContinue {
		t.Fatalf("unexpected action %v", out.Action)
	}
	if tx.MetaString("dmarc.result") != "pass" || tx.MetaString("dmarc.spf_aligned") != "true" {
		t.Fatalf("unexpected metadata: %+v", tx.MetaSnapshot())
	}
}

func TestSPFAlignmentStrict(t *testing.T) {
	setDNS(t, map[string]string{
		"_dmarc.example.com": "v=DMARC1; p=reject; aspf=s; adkim=s",
	})
	p := newPlugin(t, plugin.Options{"enforce": "reject"})
	_, out := run(t, p, "alice@sub.example.com", func(tx *plugin.Tx) {
		tx.SetMeta("spf.result", "pass")
		tx.SetMeta("spf.domain", "example.com")
	})
	if out.Action != plugin.ActionReject {
		t.Fatalf("expected strict alignment to fail, got %+v", out)
	}
}

func TestDKIMAlignment(t *testing.T) {
	setDNS(t, map[string]string{
		"_dmarc.example.com": "v=DMARC1; p=reject",
	})
	p := newPlugin(t, plugin.Options{"enforce": "reject"})
	tx, out := run(t, p, "alice@sub.example.com", func(tx *plugin.Tx) {
		tx.SetMeta("dkim.result", "pass")
		tx.SetMeta("dkim.domains", "other.example,example.com")
	})
	if out.Action != plugin.ActionContinue {
		t.Fatalf("unexpected action %v", out.Action)
	}
	if tx.MetaString("dmarc.dkim_aligned") != "true" {
		t.Fatalf("unexpected metadata: %+v", tx.MetaSnapshot())
	}
}

func TestOrganizationalDomainFallbackUsesSP(t *testing.T) {
	setDNS(t, map[string]string{
		"_dmarc.example.com": "v=DMARC1; p=reject; sp=none",
	})
	p := newPlugin(t, plugin.Options{"enforce": "reject"})
	tx, out := run(t, p, "alice@sub.example.com", nil)
	if out.Action != plugin.ActionContinue {
		t.Fatalf("subdomain policy should not reject, got %+v", out)
	}
	if tx.MetaString("dmarc.record_domain") != "example.com" {
		t.Fatalf("unexpected record domain: %+v", tx.MetaSnapshot())
	}
	if tx.MetaString("dmarc.policy") != "none" {
		t.Fatalf("expected sp=none, got %+v", tx.MetaSnapshot())
	}
}

func TestPercentZeroDisablesEnforcement(t *testing.T) {
	setDNS(t, map[string]string{
		"_dmarc.example.com": "v=DMARC1; p=reject; pct=0",
	})
	p := newPlugin(t, plugin.Options{"enforce": "reject"})
	_, out := run(t, p, "alice@example.com", nil)
	if out.Action != plugin.ActionContinue {
		t.Fatalf("pct=0 must not enforce, got %+v", out)
	}
}

func TestSkipAuthenticatedAndSubmission(t *testing.T) {
	setDNS(t, map[string]string{
		"_dmarc.example.com": "v=DMARC1; p=reject",
	})
	p := newPlugin(t, plugin.Options{"enforce": "reject"})

	tx, out := run(t, p, "alice@example.com", func(tx *plugin.Tx) { tx.AuthUser = "alice" })
	if out.Action != plugin.ActionContinue {
		t.Fatalf("authenticated mail must be skipped, got %+v", out)
	}
	if _, ok := tx.Meta("dmarc.result"); ok {
		t.Fatalf("unexpected metadata: %+v", tx.MetaSnapshot())
	}

	tx, out = run(t, p, "alice@example.com", func(tx *plugin.Tx) { tx.Mode = plugin.ModeSubmission })
	if out.Action != plugin.ActionContinue {
		t.Fatalf("submission mail must be skipped, got %+v", out)
	}
	if _, ok := tx.Meta("dmarc.result"); ok {
		t.Fatalf("unexpected metadata: %+v", tx.MetaSnapshot())
	}
}

func TestTempError(t *testing.T) {
	old := dnsLookup
	dnsLookup = func(_ context.Context, name string) ([]string, error) {
		return nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	}
	t.Cleanup(func() { dnsLookup = old })

	p := newPlugin(t, nil)
	tx, out := run(t, p, "alice@example.com", nil)
	if tx.MetaString("dmarc.result") != "temperror" {
		t.Fatalf("unexpected metadata: %+v", tx.MetaSnapshot())
	}
	if out.Action != plugin.ActionContinue {
		t.Fatalf("unexpected action %v", out.Action)
	}

	strict := newPlugin(t, plugin.Options{"tempfail_on_error": true})
	_, out = run(t, strict, "alice@example.com", nil)
	if out.Action != plugin.ActionTempFail || out.Code != 451 {
		t.Fatalf("expected tempfail, got %+v", out)
	}
}

func TestMalformedRecordIsTempError(t *testing.T) {
	setDNS(t, map[string]string{
		"_dmarc.example.com": "v=DMARC1; p=bogus",
	})
	p := newPlugin(t, nil)
	tx, _ := run(t, p, "alice@example.com", nil)
	if tx.MetaString("dmarc.result") != "temperror" {
		t.Fatalf("unexpected metadata: %+v", tx.MetaSnapshot())
	}
}

func TestFactoryValidation(t *testing.T) {
	if _, err := plugin.New("dmarc", plugin.BuildContext{BaseDir: t.TempDir()}, plugin.Options{"enforce": "bogus"}); err == nil {
		t.Fatal("expected an error for an unknown enforcement policy")
	}
}

func TestAligned(t *testing.T) {
	tests := []struct {
		from, candidate string
		mode            dmarc.AlignmentMode
		want            bool
	}{
		{"example.com", "example.com", dmarc.AlignmentRelaxed, true},
		{"sub.example.com", "example.com", dmarc.AlignmentRelaxed, true},
		{"example.com", "sub.example.com", dmarc.AlignmentRelaxed, true},
		{"sub.example.com", "example.com", dmarc.AlignmentStrict, false},
		{"sub.example.com", "sub.example.com", dmarc.AlignmentStrict, true},
		{"example.com", "example.net", dmarc.AlignmentRelaxed, false},
		{"example.com", "", dmarc.AlignmentRelaxed, false},
	}
	for _, tc := range tests {
		if got := aligned(tc.from, tc.candidate, tc.mode); got != tc.want {
			t.Errorf("aligned(%q, %q, %q) = %v, want %v", tc.from, tc.candidate, tc.mode, got, tc.want)
		}
	}
}

func TestOrganizationalDomain(t *testing.T) {
	tests := map[string]string{
		"example.com":       "example.com",
		"sub.example.com":   "example.com",
		"a.b.example.co.uk": "example.co.uk",
		"EXAMPLE.COM.":      "example.com",
		"localhost":         "localhost",
	}
	for in, want := range tests {
		if got := organizationalDomain(in); got != want {
			t.Errorf("organizationalDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEffective(t *testing.T) {
	tests := []struct {
		published dmarc.Policy
		enforce   string
		want      dmarc.Policy
	}{
		{dmarc.PolicyReject, "none", dmarc.PolicyNone},
		{dmarc.PolicyReject, "quarantine", dmarc.PolicyQuarantine},
		{dmarc.PolicyNone, "reject", dmarc.PolicyNone},
		{dmarc.PolicyQuarantine, "reject", dmarc.PolicyQuarantine},
	}
	for _, tc := range tests {
		if got := effective(tc.published, tc.enforce); got != tc.want {
			t.Errorf("effective(%q, %q) = %q, want %q", tc.published, tc.enforce, got, tc.want)
		}
	}
}
