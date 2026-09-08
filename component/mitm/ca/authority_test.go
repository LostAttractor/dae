// SPDX-License-Identifier: AGPL-3.0-only

package mitmca

import (
	"bytes"
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
	"testing"
	"time"
)

func testAuthority(t *testing.T) (*Authority, string, string) {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	if err := Generate(certPath, keyPath, "dae test CA", 48*time.Hour); err != nil {
		t.Fatal(err)
	}
	a, err := Load(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return a, certPath, keyPath
}

func TestGenerateProtectsExistingFiles(t *testing.T) {
	_, certPath, keyPath := testAuthority(t)
	beforeCert, _ := os.ReadFile(certPath)
	beforeKey, _ := os.ReadFile(keyPath)
	if err := Generate(certPath, keyPath, "replacement", time.Hour); err == nil {
		t.Fatal("overwrote existing CA")
	}
	afterCert, _ := os.ReadFile(certPath)
	afterKey, _ := os.ReadFile(keyPath)
	if !bytes.Equal(beforeCert, afterCert) || !bytes.Equal(beforeKey, afterKey) {
		t.Fatal("failed generation changed existing CA")
	}
	info, err := os.Stat(keyPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private key permissions: %v, %v", info, err)
	}
	newKey := filepath.Join(t.TempDir(), "key.pem")
	if err := Generate(certPath, newKey, "replacement", time.Hour); err == nil {
		t.Fatal("generation accepted an existing certificate")
	}
	if _, err := os.Stat(newKey); !os.IsNotExist(err) {
		t.Fatalf("generation left a mismatched key: %v", err)
	}
	alias := filepath.Join(t.TempDir(), "link.pem")
	if err := os.Symlink(certPath, alias); err != nil {
		t.Fatal(err)
	}
	if err := Generate(alias, newKey, "replacement", time.Hour); err == nil {
		t.Fatal("generation followed an existing symlink")
	}
	if err := Generate(newKey, newKey, "replacement", time.Hour); err == nil {
		t.Fatal("generation accepted identical certificate and key paths")
	}
}

func TestLoadRejectsMismatchedAndPublicKeys(t *testing.T) {
	_, certPath, keyPath := testAuthority(t)
	_, _, otherKey := testAuthority(t)
	if _, err := Load(certPath, otherKey); err == nil {
		t.Fatal("loaded a CA with a different private key")
	}
	if err := os.Chmod(keyPath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(certPath, keyPath); err == nil {
		t.Fatal("loaded a world-readable private key")
	}
}

func TestReadExpiredRootAllowsInspectionButLoadRefuses(t *testing.T) {
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "expired"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "expired.cer")
	keyPath := filepath.Join(dir, "expired.key")
	if err := os.WriteFile(certPath, der, 0644); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCertificate(certPath); err != nil {
		t.Fatalf("cannot inspect expired DER root: %v", err)
	}
	if _, err := Load(certPath, keyPath); err == nil {
		t.Fatal("loaded expired root")
	}
	root.IsCA = false
	der, err = x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseCertificate(der); err == nil {
		t.Fatal("accepted non-CA certificate")
	}
}

func TestLeafValidityStopsAtRootExpiration(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	if err := Generate(certPath, keyPath, "short-lived CA", time.Hour); err != nil {
		t.Fatal(err)
	}
	a, err := Load(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := a.serverCertificate("test.example")
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.Leaf.NotAfter.Equal(a.certificate.NotAfter) {
		t.Fatalf("leaf expiry %v differs from short-lived CA expiry %v", leaf.Leaf.NotAfter, a.certificate.NotAfter)
	}
}

func TestIssuedCertificatesVerifyAndCacheExpires(t *testing.T) {
	a, _, _ := testAuthority(t)
	pool := x509.NewCertPool()
	pool.AddCert(a.certificate)
	for _, host := range []string{"example.com", "127.0.0.1", "2001:db8::1"} {
		cert, err := a.TLSConfig(host).GetCertificate(&tls.ClientHelloInfo{ServerName: host})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: host}); err != nil {
			t.Fatalf("issued certificate does not verify for %s: %v", host, err)
		}
		if cert.Leaf.NotAfter.After(a.certificate.NotAfter) || cert.Leaf.NotAfter.Sub(time.Now()) > 24*time.Hour {
			t.Fatal("leaf validity exceeds CA or 24 hours")
		}
	}
	first, _ := a.serverCertificate("example.com")
	cached, _ := a.serverCertificate("EXAMPLE.COM.")
	if first != cached {
		t.Fatal("equivalent hosts missed cache")
	}
	first.Leaf.NotAfter = time.Now().Add(-time.Second)
	renewed, err := a.serverCertificate("example.com")
	if err != nil || first == renewed {
		t.Fatalf("expired cached certificate not renewed: %v", err)
	}
	for i := 0; i < maxCachedCertificates+1; i++ {
		if _, err := a.serverCertificate(fmt.Sprintf("host%d.example.com", i)); err != nil {
			t.Fatal(err)
		}
	}
	if len(a.cache) != maxCachedCertificates || a.lru.Len() != maxCachedCertificates {
		t.Fatalf("unbounded certificate cache: %d/%d", len(a.cache), a.lru.Len())
	}
	if a.cache["example.com"] != nil {
		t.Fatal("least recently used certificate was not evicted")
	}
	a.certificate.NotAfter = time.Now().Add(-time.Second)
	if _, err := a.serverCertificate("host256.example.com"); err == nil {
		t.Fatal("cached leaf was returned after CA expiration")
	}
}

func TestIssuerRejectsInvalidServerNames(t *testing.T) {
	a, _, _ := testAuthority(t)
	for _, host := range []string{"", "*", "*.example.com", "example.com:443", "foo..bar", "-bad.example", "bad-.example", "example.com/path", "bad\x00.example", "例子.example"} {
		if _, err := a.serverCertificate(host); err == nil {
			t.Errorf("accepted invalid hostname %q", host)
		}
	}
}

func TestAuthorityTLSHandshake(t *testing.T) {
	a, _, _ := testAuthority(t)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.certificate.Raw}))
	for _, test := range []struct {
		host, serverName string
		reject           bool
	}{
		{"test.example", "test.example", false},
		{"TEST.EXAMPLE.", "test.example", false},
		{"127.0.0.1", "127.0.0.1", false},
		{"2001:db8::1", "2001:db8::1", false},
		{"test.example", "different.example", true},
		{"test.example", "127.0.0.1", true},
		{"127.0.0.1", "test.example", true},
	} {
		t.Run(test.host+"/"+test.serverName, func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			_ = left.SetDeadline(time.Now().Add(5 * time.Second))
			_ = right.SetDeadline(time.Now().Add(5 * time.Second))
			client := tls.Client(left, &tls.Config{RootCAs: pool, ServerName: test.serverName, NextProtos: []string{"http/1.1"}})
			server := tls.Server(right, a.TLSConfig(test.host))
			result := make(chan error, 1)
			go func() { result <- server.Handshake() }()
			clientErr, serverErr := client.Handshake(), <-result
			if test.reject {
				if clientErr == nil || serverErr == nil {
					t.Fatalf("accepted mismatched identity: client=%v server=%v", clientErr, serverErr)
				}
				return
			}
			if clientErr != nil || serverErr != nil {
				t.Fatalf("handshake failed: client=%v server=%v", clientErr, serverErr)
			}
			if got := client.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
				t.Fatalf("ALPN = %q", got)
			}
			if net.ParseIP(test.host) != nil && server.ConnectionState().ServerName != "" {
				t.Fatal("IP handshake did not exercise the absent SNI case")
			}
		})
	}
}
