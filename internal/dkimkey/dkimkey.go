// Package dkimkey generates and parses DKIM signing keys.
package dkimkey

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
)

// Key is a parsed DKIM private key.
type Key struct {
	Signer crypto.Signer
	Algo   string // "rsa" or "ed25519"
	Bits   int    // RSA modulus size, 0 for ed25519
}

// GenerateRSA creates a new RSA private key and returns it with its PEM
// encoding and the matching DKIM DNS TXT value.
func GenerateRSA(bits int) (*Key, string, string, error) {
	if bits == 0 {
		bits = 2048
	}
	if bits < 1024 {
		return nil, "", "", fmt.Errorf("RSA key must be at least 1024 bits")
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, "", "", err
	}
	key := &Key{Signer: priv, Algo: "rsa", Bits: bits}
	pemStr := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}))
	txt, err := DNSRecord(key)
	if err != nil {
		return nil, "", "", err
	}
	return key, pemStr, txt, nil
}

// GenerateEd25519 creates a new Ed25519 key.
func GenerateEd25519() (*Key, string, string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, "", "", err
	}
	key := &Key{Signer: priv, Algo: "ed25519"}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	txt, err := DNSRecord(key)
	if err != nil {
		return nil, "", "", err
	}
	return key, pemStr, txt, nil
}

// ParsePEM parses an RSA (PKCS#1 or PKCS#8) or Ed25519 (PKCS#8) private key.
func ParsePEM(data []byte) (*Key, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return &Key{Signer: key, Algo: "rsa", Bits: key.N.BitLen()}, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	switch key := parsed.(type) {
	case *rsa.PrivateKey:
		return &Key{Signer: key, Algo: "rsa", Bits: key.N.BitLen()}, nil
	case ed25519.PrivateKey:
		return &Key{Signer: key, Algo: "ed25519"}, nil
	default:
		return nil, fmt.Errorf("unsupported key type %T (use RSA or Ed25519)", parsed)
	}
}

// DNSRecord returns the DKIM public key TXT record value (without the
// selector._domainkey. prefix).
func DNSRecord(k *Key) (string, error) {
	if k == nil || k.Signer == nil {
		return "", fmt.Errorf("nil key")
	}
	switch pub := k.Signer.Public().(type) {
	case *rsa.PublicKey:
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return "", err
		}
		return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der), nil
	case ed25519.PublicKey:
		return "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(pub), nil
	default:
		return "", fmt.Errorf("unsupported public key type %T", pub)
	}
}

// RecordName returns the fully-qualified DNS name for the selector.
func RecordName(selector, domain string) string {
	selector = strings.TrimSpace(selector)
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if selector == "" {
		selector = "default"
	}
	if domain == "" {
		return selector + "._domainkey"
	}
	return selector + "._domainkey." + domain + "."
}
