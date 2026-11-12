// Package tlsutil loads or creates the TLS material used by SMTP listeners.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Ensure loads cert/key, generating a self-signed certificate when allowed.
func Ensure(certFile, keyFile, hostname string, autoGenerate bool, minVersion uint16) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("tls cert_file and key_file are required")
	}
	_, certErr := os.Stat(certFile)
	_, keyErr := os.Stat(keyFile)
	if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
		if !autoGenerate {
			return nil, fmt.Errorf("TLS files not found (cert=%s key=%s); run `gomta init` or set tls.auto_generate", certFile, keyFile)
		}
		if err := GenerateSelfSigned(certFile, keyFile, hostname); err != nil {
			return nil, err
		}
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS keypair: %w", err)
	}
	if minVersion == 0 {
		minVersion = tls.VersionTLS12
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVersion,
	}, nil
}

// GenerateSelfSigned writes a one-year ECDSA certificate for hostname,
// localhost, and loopback addresses.
func GenerateSelfSigned(certFile, keyFile, hostname string) error {
	if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err != nil {
		return fmt.Errorf("create TLS directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
		return fmt.Errorf("create TLS directory: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate TLS key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	now := time.Now()
	hosts := []string{"localhost", hostname}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if ip := net.ParseIP(hostname); ip != nil {
		ips = append(ips, ip)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname, Organization: []string{"GoMTA self-signed"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     hosts,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create self-signed certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	return nil
}
