// SPDX-License-Identifier: AGPL-3.0-only

// Package mitmca manages the local certificate authority used for HTTPS modules.
package mitmca

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const maxCachedCertificates = 256

type cachedCertificate struct {
	host string
	cert *tls.Certificate
}

// Authority holds a root CA and a bounded cache of short-lived server certificates.
type Authority struct {
	certificate *x509.Certificate
	key         any
	mu          sync.Mutex
	cache       map[string]*list.Element
	lru         list.List
}

// Generate creates an ECDSA root certificate and unencrypted PKCS#8 private key.
// Existing files (including symlinks) are never overwritten. New parent
// directories are private, as is the key; the certificate is public.
func Generate(certPath, keyPath, commonName string, validity time.Duration) error {
	if strings.TrimSpace(commonName) == "" || validity <= 0 {
		return fmt.Errorf("CA name and positive validity are required")
	}
	if certPath == "" || keyPath == "" {
		return fmt.Errorf("certificate and key paths are required")
	}
	certAbs, err := filepath.Abs(certPath)
	if err != nil {
		return err
	}
	keyAbs, err := filepath.Abs(keyPath)
	if err != nil {
		return err
	}
	if certAbs == keyAbs {
		return fmt.Errorf("certificate and key paths must be different")
	}
	for _, path := range []string{certPath, keyPath} {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("refusing to overwrite %s", path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	root := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"dae"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	for _, path := range []string{certPath, keyPath} {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
	}
	if err := writeNewFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		return err
	}
	if err := writeNewFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		_ = os.Remove(keyPath)
		return err
	}
	return nil
}

func writeNewFile(path string, data []byte, mode os.FileMode) (err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer func() {
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

// ReadCertificate reads a single self-signed root CA in PEM or DER format.
// Its validity dates are intentionally not enforced, allowing expired CAs to
// be inspected and removed from devices.
func ReadCertificate(path string) (*x509.Certificate, error) {
	data, err := readFile(path, false)
	if err != nil {
		return nil, err
	}
	return parseCertificate(data)
}

func parseCertificate(data []byte) (*x509.Certificate, error) {
	if block, rest := pem.Decode(data); block != nil {
		if block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
			return nil, fmt.Errorf("expected one PEM CERTIFICATE block")
		}
		data = block.Bytes
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("certificate is not a signing CA")
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return nil, fmt.Errorf("certificate must be a self-signed root CA: %w", err)
	}
	return cert, nil
}

func readFile(path string, private bool) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if private && info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("CA private key %s must not be accessible to group or others (use chmod 600)", path)
	}
	const maxFileSize = 1 << 20
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("certificate/key file exceeds 1 MiB")
	}
	return data, nil
}

// Load loads and validates a root CA and its matching private key. It refuses
// expired or not-yet-valid authorities and never generates or rotates a CA.
func Load(certPath, keyPath string) (*Authority, error) {
	cert, err := ReadCertificate(certPath)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return nil, fmt.Errorf("CA certificate is outside its validity period (%s to %s)", cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	}
	keyPEM, err := readFile(keyPath, true)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(CertificatePEM(cert), keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load CA key pair: %w", err)
	}
	return &Authority{certificate: cert, key: pair.PrivateKey, cache: make(map[string]*list.Element)}, nil
}

// TLSConfig issues a server certificate for the ClientHello's SNI. It advertises
// HTTP/1.1 by default; callers may enable additional protocols they support.
// Callers must select eligible MITM connections before the TLS handshake.
func (a *Authority) Fingerprint() string {
	if a == nil || a.certificate == nil {
		return ""
	}
	return Fingerprint(a.certificate)
}

func (a *Authority) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return a.serverCertificate(hello.ServerName)
		},
	}
}

func (a *Authority) serverCertificate(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if err := validateHost(host); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if now.Before(a.certificate.NotBefore) || !now.Before(a.certificate.NotAfter) {
		return nil, fmt.Errorf("MITM CA is outside its validity period")
	}
	if entry := a.cache[host]; entry != nil {
		cert := entry.Value.(cachedCertificate).cert
		if now.Before(cert.Leaf.NotAfter) {
			a.lru.MoveToFront(entry)
			return cert, nil
		}
		delete(a.cache, host)
		a.lru.Remove(entry)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	notBefore, notAfter := now.Add(-5*time.Minute), now.Add(24*time.Hour)
	if notBefore.Before(a.certificate.NotBefore) {
		notBefore = a.certificate.NotBefore
	}
	if notAfter.After(a.certificate.NotAfter) {
		notAfter = a.certificate.NotAfter
	}
	leaf := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		leaf.IPAddresses = []net.IP{ip}
	} else {
		leaf.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, a.certificate, &key.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	leaf, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pair := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	a.cache[host] = a.lru.PushFront(cachedCertificate{host, pair})
	if a.lru.Len() > maxCachedCertificates {
		oldest := a.lru.Back()
		delete(a.cache, oldest.Value.(cachedCertificate).host)
		a.lru.Remove(oldest)
	}
	return pair, nil
}

func validateHost(host string) error {
	if net.ParseIP(host) != nil {
		return nil
	}
	if len(host) == 0 || len(host) > 253 {
		return fmt.Errorf("missing or invalid TLS server name")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("invalid TLS server name %q", host)
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return fmt.Errorf("invalid TLS server name %q", host)
			}
		}
	}
	return nil
}

func randomSerial() (*big.Int, error) {
	// Add one to ensure a positive serial even if the random number is zero.
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	return n.Add(n, big.NewInt(1)), nil
}
