// SPDX-License-Identifier: AGPL-3.0-only
package testutil

import (
	"crypto/x509"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TLSRoots(server *httptest.Server) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	return pool
}
func TLSFile(t *testing.T, server *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
