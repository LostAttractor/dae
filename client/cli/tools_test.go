// SPDX-License-Identifier: AGPL-3.0-only
package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestDownloadCommandsPreserveOutputOnFailure(t *testing.T) {
	for _, tool := range []struct {
		name          string
		newCommand    func() *cobra.Command
		args, invalid []string
	}{
		{"certificate", NewCertificateCommand, []string{"download"}, []string{"download", "--format", "invalid"}},
		{"pprof", NewPprofCommand, []string{"heap"}, []string{"invalid"}},
	} {
		for _, failure := range []string{"invalid", "unauthorized", "interrupted", "unreachable", "success"} {
			t.Run(tool.name+"/"+failure, func(t *testing.T) {
				t.Setenv("DAE_API_KEY", "")
				t.Setenv("DAE_API_KEY_FILE", "")
				t.Setenv("DAE_API_CA", "")
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch failure {
					case "invalid":
						t.Error("invalid arguments reached the server")
					case "unauthorized":
						http.Error(w, "key required", http.StatusUnauthorized)
					case "interrupted":
						w.Header().Set("Content-Length", "100")
						io.WriteString(w, "partial")
					default:
						io.WriteString(w, "complete download")
					}
				}))
				defer server.Close()
				if failure == "unreachable" {
					server.Close()
				}
				dir := t.TempDir()
				path := filepath.Join(dir, "output")
				if err := os.WriteFile(path, []byte("existing data"), 0600); err != nil {
					t.Fatal(err)
				}
				args := tool.args
				if failure == "invalid" {
					args = tool.invalid
				}
				command := tool.newCommand()
				command.SetOut(io.Discard)
				command.SetErr(io.Discard)
				command.SetArgs(append(append([]string{}, args...), "--api", server.URL, "--output", path))
				err := command.Execute()
				if (err == nil) != (failure == "success") {
					t.Fatalf("unexpected result: %v", err)
				}
				want := "existing data"
				if failure == "success" {
					want = "complete download"
				}
				data, err := os.ReadFile(path)
				if err != nil || string(data) != want {
					t.Fatalf("output = %q, %v", data, err)
				}
				entries, err := os.ReadDir(dir)
				if err != nil || len(entries) != 1 {
					t.Fatalf("temporary file leaked: %v, %v", entries, err)
				}
				if failure == "success" {
					var stdout bytes.Buffer
					command = tool.newCommand()
					command.SetOut(&stdout)
					command.SetArgs(append(append([]string{}, args...), "--api", server.URL))
					if err := command.Execute(); err != nil || stdout.String() != want {
						t.Fatalf("stdout = %q, %v", stdout.String(), err)
					}
				}
			})
		}
	}
}

func TestPprofDefaultTimeoutAndAPICAPinning(t *testing.T) {
	flag := NewPprofCommand().Flags().Lookup("timeout")
	if flag == nil || flag.DefValue != "1m0s" || flag.Value.String() != "1m0s" {
		t.Fatalf("pprof timeout flag = %+v", flag)
	}

	startTLSServer := func(serial int64) (*httptest.Server, []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: "test-api"},
			NotBefore:             time.Now().Add(-time.Minute),
			NotAfter:              time.Now().Add(time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  true,
			IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, `{"name":"pinned","fingerprint":"fp"}`)
		}))
		server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
		server.StartTLS()
		t.Cleanup(server.Close)
		return server, der
	}

	pinned, pinnedDER := startTLSServer(1)
	other, _ := startTLSServer(2)

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pinnedDER})
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}

	for _, target := range []struct {
		url    string
		wantOK bool
	}{
		{pinned.URL, true},
		{other.URL, false},
	} {
		command := NewCertificateCommand()
		command.SetOut(io.Discard)
		command.SetErr(io.Discard)
		command.SetArgs([]string{"info", "--api", target.url, "--api-ca", caFile})
		err := command.Execute()
		if (err == nil) != target.wantOK {
			t.Fatalf("url=%s err=%v wantOK=%v", target.url, err, target.wantOK)
		}
	}
}
