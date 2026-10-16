// SPDX-License-Identifier: AGPL-3.0-only

package ca

import (
	"context"
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
	maxCachedCertificates  = 256
	maxConcurrentIssuances = 4
	leafLifetime           = 24 * time.Hour
)

type cachedCertificate struct {
	key  string
	cert *tls.Certificate
}

type certificateIssue struct {
	done chan struct{}
	cert *tls.Certificate
	err  error
}

// ServerCertificate issues or reuses a leaf covering only the ingress host.
func (a *Authority) ServerCertificate(host string) (*tls.Certificate, error) {
	return a.serverCertificate(context.Background(), host)
}

func (a *Authority) serverCertificate(ctx context.Context, host string) (*tls.Certificate, error) {
	host = normalizeHost(host)
	if err := validateHost(host); err != nil {
		return nil, err
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		now := time.Now()
		if now.Before(a.certificate.NotBefore) || !now.Before(a.certificate.NotAfter) {
			return nil, fmt.Errorf("CA is outside its validity period")
		}
		a.mu.Lock()
		if entry := a.cache[host]; entry != nil {
			cert := entry.Value.(cachedCertificate).cert
			if now.Before(cert.Leaf.NotAfter) {
				a.lru.MoveToFront(entry)
				a.mu.Unlock()
				return cert, nil
			}
			delete(a.cache, host)
			a.lru.Remove(entry)
		}
		if issue := a.issuing[host]; issue != nil {
			a.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-issue.done:
				return issue.cert, issue.err
			}
		}
		if len(a.issuing) >= maxConcurrentIssuances {
			changed := a.issuanceChanged
			a.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-changed:
				continue
			}
		}
		if a.issuing == nil {
			a.issuing = make(map[string]*certificateIssue)
			a.issuanceChanged = make(chan struct{})
		}
		issue := &certificateIssue{done: make(chan struct{})}
		a.issuing[host] = issue
		a.mu.Unlock()

		// Random-key generation, signing and chain verification hold no cache lock.
		// Only admitted hosts allocate an issuance record; waiters remain callers.
		cert, err := a.signCertificate(host, now, leafLifetime)
		a.mu.Lock()
		if err == nil {
			a.cache[host] = a.lru.PushFront(cachedCertificate{key: host, cert: cert})
			if a.lru.Len() > maxCachedCertificates {
				oldest := a.lru.Back()
				delete(a.cache, oldest.Value.(cachedCertificate).key)
				a.lru.Remove(oldest)
			}
		}
		issue.cert, issue.err = cert, err
		delete(a.issuing, host)
		close(issue.done)
		close(a.issuanceChanged)
		a.issuanceChanged = make(chan struct{})
		a.mu.Unlock()
		return cert, err
	}
}

func (a *Authority) signCertificate(host string, now time.Time, lifetime time.Duration) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	notBefore, notAfter := now.Add(-5*time.Minute), now.Add(lifetime)
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
