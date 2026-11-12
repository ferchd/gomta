package dkimkey

import (
	"crypto/ed25519"
	"crypto/rsa"
	"strings"
	"testing"
)

func TestGenerateRSAAndParse(t *testing.T) {
	key, pemStr, txt, err := GenerateRSA(1024)
	if err != nil {
		t.Fatal(err)
	}
	if key.Algo != "rsa" || key.Bits != 1024 {
		t.Fatalf("unexpected key metadata: %+v", key)
	}
	if _, ok := key.Signer.(*rsa.PrivateKey); !ok {
		t.Fatalf("unexpected signer type %T", key.Signer)
	}
	if !strings.HasPrefix(txt, "v=DKIM1; k=rsa; p=") {
		t.Fatalf("unexpected DNS record %q", txt)
	}
	if !strings.Contains(pemStr, "BEGIN RSA PRIVATE KEY") {
		t.Fatalf("unexpected PEM:\n%s", pemStr)
	}

	parsed, err := ParsePEM([]byte(pemStr))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Algo != "rsa" || parsed.Bits != 1024 {
		t.Fatalf("unexpected parsed key metadata: %+v", parsed)
	}
	again, err := DNSRecord(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if again != txt {
		t.Fatalf("DNS record changed after parse:\n%s\n%s", txt, again)
	}
}

func TestGenerateRSARejectsSmallKeys(t *testing.T) {
	if _, _, _, err := GenerateRSA(512); err == nil {
		t.Fatal("expected an error for a 512-bit key")
	}
}

func TestGenerateEd25519AndParse(t *testing.T) {
	key, pemStr, txt, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	if key.Algo != "ed25519" || key.Bits != 0 {
		t.Fatalf("unexpected key metadata: %+v", key)
	}
	if _, ok := key.Signer.(ed25519.PrivateKey); !ok {
		t.Fatalf("unexpected signer type %T", key.Signer)
	}
	if !strings.HasPrefix(txt, "v=DKIM1; k=ed25519; p=") {
		t.Fatalf("unexpected DNS record %q", txt)
	}

	parsed, err := ParsePEM([]byte(pemStr))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Algo != "ed25519" {
		t.Fatalf("unexpected parsed key: %+v", parsed)
	}
}

func TestParsePEMErrors(t *testing.T) {
	if _, err := ParsePEM([]byte("not a pem file")); err == nil {
		t.Fatal("expected an error for non-PEM input")
	}
}

func TestDNSRecordNil(t *testing.T) {
	if _, err := DNSRecord(nil); err == nil {
		t.Fatal("expected an error for a nil key")
	}
}

func TestRecordName(t *testing.T) {
	tests := []struct {
		selector, domain, want string
	}{
		{"default", "example.com", "default._domainkey.example.com."},
		{"", "example.com", "default._domainkey.example.com."},
		{"mail", "example.com.", "mail._domainkey.example.com."},
		{"default", "", "default._domainkey"},
	}
	for _, tc := range tests {
		if got := RecordName(tc.selector, tc.domain); got != tc.want {
			t.Errorf("RecordName(%q, %q) = %q, want %q", tc.selector, tc.domain, got, tc.want)
		}
	}
}
