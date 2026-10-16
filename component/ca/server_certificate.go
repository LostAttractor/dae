// SPDX-License-Identifier: AGPL-3.0-only

package ca

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/daeuniverse/dae/common/persist"
)

const serverCertificateLifetime = 90 * 24 * time.Hour

// PersistentServerCertificate reuses a private PEM containing a leaf and its key.
// Only an absent or expired leaf is renewed; invalid stored identities are errors.
// The caller owns the path and serializes access.
func (a *Authority) PersistentServerCertificate(path, host string) (*tls.Certificate, error) {
	data, err := readFile(path, true)
	if errors.Is(err, os.ErrNotExist) {
		return a.renewServerCertificate(path, host)
	}
	if err != nil {
		return nil, err
	}
	leaf, err := tls.X509KeyPair(data, data)
	if err != nil {
		return nil, fmt.Errorf("load server certificate %s: %w", path, err)
	}
	if len(leaf.Certificate) != 1 || leaf.Leaf.IsCA {
		return nil, fmt.Errorf("server certificate %s must contain one leaf", path)
	}
	roots := x509.NewCertPool()
	roots.AddCert(a.certificate)
	now := time.Now()
	// Validate an expired leaf at the end of its lifetime before renewing it.
	// Corruption, another issuer or another host must not silently replace it.
	verifyTime := now
	if !now.Before(leaf.Leaf.NotAfter) {
		verifyTime = leaf.Leaf.NotAfter.Add(-time.Second)
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host, CurrentTime: verifyTime}); err != nil {
		return nil, fmt.Errorf("verify stored server certificate %s: %w", path, err)
	}
	if !now.Before(leaf.Leaf.NotAfter) {
		return a.renewServerCertificate(path, host)
	}
	return &leaf, nil
}

// TemporaryServerCertificate issues a fresh leaf and key without storing or
// caching them. Its lifetime never exceeds the CA's remaining validity.
func (a *Authority) TemporaryServerCertificate(host string, lifetime time.Duration) (*tls.Certificate, error) {
	host = normalizeHost(host)
	if err := validateHost(host); err != nil {
		return nil, err
	}
	if lifetime <= 0 {
		return nil, fmt.Errorf("server certificate lifetime must be positive")
	}
	return a.signCertificate(host, time.Now(), lifetime)
}

// A returned leaf with an error has been published but its durability is uncertain.
func (a *Authority) renewServerCertificate(path, host string) (*tls.Certificate, error) {
	leaf, err := a.TemporaryServerCertificate(host, serverCertificateLifetime)
	if err != nil {
		return nil, err
	}
	err = writeServerCertificate(path, leaf)
	if !persist.Published(err) {
		return nil, err
	}
	return leaf, err
}

func writeServerCertificate(path string, leaf *tls.Certificate) error {
	key, err := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey)
	if err != nil {
		return err
	}
	data := append(CertificatePEM(leaf.Leaf), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})...)
	directory := filepath.Dir(path)
	if err := persist.MkdirAll(directory, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".server-certificate-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	return persist.AfterPublish(persist.SyncDir(directory))
}
