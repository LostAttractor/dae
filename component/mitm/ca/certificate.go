// SPDX-License-Identifier: AGPL-3.0-only

package mitmca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	maxCachedCertificates = 256
	leafLifetime          = 24 * time.Hour
)

type cachedCertificate struct {
	key  string
	cert *tls.Certificate
}

// ServerCertificate issues or reuses a leaf covering only the ingress host.
func (a *Authority) ServerCertificate(host string) (*tls.Certificate, error) {
	host = normalizeHost(host)
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
	cert, err := a.signCertificate(host, now)
	if err != nil {
		return nil, err
	}
	a.cache[host] = a.lru.PushFront(cachedCertificate{key: host, cert: cert})
	if a.lru.Len() > maxCachedCertificates {
		oldest := a.lru.Back()
		delete(a.cache, oldest.Value.(cachedCertificate).key)
		a.lru.Remove(oldest)
	}
	return cert, nil
}

func (a *Authority) signCertificate(host string, now time.Time) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	notBefore, notAfter := now.Add(-5*time.Minute), now.Add(leafLifetime)
	if notBefore.Before(a.certificate.NotBefore) {
		notBefore = a.certificate.NotBefore
	}
	if notAfter.After(a.certificate.NotAfter) {
		notAfter = a.certificate.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.certificate, &key.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	// Enforce local issuer constraints before returning or caching the leaf.
	roots := x509.NewCertPool()
	roots.AddCert(a.certificate)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host, CurrentTime: now}); err != nil {
		return nil, fmt.Errorf("verify certificate under local CA: %w", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

func normalizeHost(host string) string { return strings.ToLower(strings.TrimSuffix(host, ".")) }

func validateHost(host string) error {
	if net.ParseIP(host) != nil {
		return nil
	}
	if len(host) == 0 || len(host) > 253 {
		return fmt.Errorf("missing or invalid TLS server name")
	}
	for label := range strings.SplitSeq(host, ".") {
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
