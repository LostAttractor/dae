// SPDX-License-Identifier: AGPL-3.0-only

package ca

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestManagedCAConcurrentInitializationAndReuse(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	fingerprints := make(chan string, 12)
	var workers sync.WaitGroup
	for range 12 {
		workers.Go(func() {
			authority, err := Ensure(dir)
			if err != nil {
				t.Error(err)
				return
			}
			fingerprints <- authority.Fingerprint()
		})
	}
	workers.Wait()
	close(fingerprints)
	var fingerprint string
	for got := range fingerprints {
		if fingerprint != "" && got != fingerprint {
			t.Fatal("concurrent initialization replaced the identity")
		}
		fingerprint = got
	}
	if fingerprint == "" {
		t.Fatal("no identity initialized")
	}
	cert, key := ManagedPaths(dir)
	beforeCert, _ := os.ReadFile(cert)
	beforeKey, _ := os.ReadFile(key)
	authority, err := Ensure(dir)
	if err != nil || authority.Fingerprint() != fingerprint {
		t.Fatal("restart changed the identity", err)
	}
	afterCert, _ := os.ReadFile(cert)
	afterKey, _ := os.ReadFile(key)
	if string(beforeCert) != string(afterCert) || string(beforeKey) != string(afterKey) {
		t.Fatal("reload rewrote CA files")
	}
	for path, want := range map[string]os.FileMode{dir: 0700, key: 0600, cert: 0644} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("permissions for %s: %v, %v", path, info, err)
		}
	}
	if err := Initialize(dir, "replacement", time.Hour); err == nil {
		t.Fatal("explicit initialization replaced an existing identity")
	}
}

func TestManagedCARejectsBrokenExistingStore(t *testing.T) {
	for _, damage := range []string{"missing certificate", "missing key", "both missing", "invalid certificate", "invalid key", "open key", "expired", "symlink"} {
		t.Run(damage, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "pki")
			if err := Initialize(dir, "test", time.Hour); err != nil {
				t.Fatal(err)
			}
			cert, key := ManagedPaths(dir)
			switch damage {
			case "missing certificate":
				os.Remove(cert)
			case "missing key":
				os.Remove(key)
			case "both missing":
				os.Remove(cert)
				os.Remove(key)
			case "invalid certificate":
				os.WriteFile(cert, []byte("broken"), 0644)
			case "invalid key":
				os.WriteFile(key, []byte("broken"), 0600)
			case "open key":
				os.Chmod(key, 0644)
			case "expired":
				os.Remove(cert)
				os.Remove(key)
				if err := Generate(cert, key, "expired", time.Nanosecond); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				other := dir + "-other"
				if err := os.Rename(dir, other); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, dir); err != nil {
					t.Fatal(err)
				}
			}
			beforeCert, certErr := os.ReadFile(cert)
			beforeKey, keyErr := os.ReadFile(key)
			if _, err := Ensure(dir); err == nil {
				t.Fatal("broken store silently recovered")
			}
			afterCert, nextCertErr := os.ReadFile(cert)
			afterKey, nextKeyErr := os.ReadFile(key)
			if string(beforeCert) != string(afterCert) || string(beforeKey) != string(afterKey) || (certErr == nil) != (nextCertErr == nil) || (keyErr == nil) != (nextKeyErr == nil) {
				t.Fatal("broken store was modified")
			}
		})
	}
}
