// SPDX-License-Identifier: AGPL-3.0-only

package ca

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPersistentServerCertificateLifecycle(t *testing.T) {
	authority, certPath, keyPath := testAuthority(t)
	path := filepath.Join(t.TempDir(), "api-tls", "127.0.0.1.pem")
	shared, err := authority.ServerCertificate("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	first, err := authority.PersistentServerCertificate(path, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !first.Leaf.NotAfter.Equal(authority.certificate.NotAfter) {
		t.Fatal("persistent leaf must stop at this short-lived CA's expiration")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private identity permissions: %v, %v", info, err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := Load(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	reused, err := restarted.PersistentServerCertificate(path, "127.0.0.1")
	if err != nil || !bytes.Equal(first.Leaf.Raw, reused.Leaf.Raw) {
		t.Fatal("restart changed the server certificate", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("loading rewrote the stored identity", err)
	}
	temporary, err := authority.TemporaryServerCertificate("127.0.0.1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Leaf.Raw, temporary.Leaf.Raw) || bytes.Equal(first.Leaf.RawSubjectPublicKeyInfo, temporary.Leaf.RawSubjectPublicKeyInfo) {
		t.Fatal("temporary issuance reused the persistent leaf or key")
	}
	if remaining := time.Until(temporary.Leaf.NotAfter); remaining <= 0 || remaining > time.Minute {
		t.Fatalf("temporary certificate lifetime: %v", remaining)
	}
	second, err := authority.TemporaryServerCertificate("127.0.0.1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(temporary.Leaf.RawSubjectPublicKeyInfo, second.Leaf.RawSubjectPublicKeyInfo) {
		t.Fatal("temporary issuance reused a previous test's key")
	}
	reused, err = restarted.PersistentServerCertificate(path, "127.0.0.1")
	if err != nil || !bytes.Equal(first.Leaf.Raw, reused.Leaf.Raw) {
		t.Fatal("temporary issuance replaced the persistent identity", err)
	}
	after, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("temporary issuance changed the stored identity", err)
	}
	if cached, _ := authority.ServerCertificate("127.0.0.1"); cached != shared {
		t.Fatal("persistent issuance changed the MITM signing cache")
	}
	expired, err := authority.signCertificate("127.0.0.1", time.Now().Add(-2*time.Minute), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeServerCertificate(path, expired); err != nil {
		t.Fatal(err)
	}
	valid, err := restarted.PersistentServerCertificate(path, "127.0.0.1")
	if err != nil || !valid.Leaf.NotAfter.After(time.Now()) || bytes.Equal(valid.Leaf.Raw, expired.Leaf.Raw) {
		t.Fatal("expired leaf was not renewed", err)
	}
}

func TestPersistentServerCertificateRejectsInvalidStore(t *testing.T) {
	authority, _, _ := testAuthority(t)
	other, _, _ := testAuthority(t)
	for _, scenario := range []string{"corrupt", "wrong-host", "wrong-ca", "public-key-file"} {
		t.Run(scenario, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "server.pem")
			issuer, host := authority, "127.0.0.1"
			if scenario == "wrong-ca" {
				issuer = other
			}
			if scenario == "wrong-host" {
				host = "127.0.0.2"
			}
			if _, err := issuer.PersistentServerCertificate(path, host); err != nil {
				t.Fatal(err)
			}
			if scenario == "corrupt" {
				if err := os.WriteFile(path, []byte("invalid identity"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "public-key-file" {
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := authority.PersistentServerCertificate(path, "127.0.0.1"); err == nil {
				t.Fatal("invalid identity was accepted or silently replaced")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed load changed the stored identity", err)
			}
		})
	}
}
