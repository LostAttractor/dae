// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	localca "github.com/daeuniverse/dae/component/ca"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/internal/apiserver"
)

func TestCertificatePreparationLifecycle(t *testing.T) {
	base := t.TempDir()
	t.Setenv("DAE_LOCATION_CACHE", base)
	conf := mitmConfigForTest(t, "")
	if got, err := prepareCertificates(conf, nil); err != nil || got != nil {
		t.Fatalf("unused CA: %v, %v", got, err)
	}
	if entries, _ := os.ReadDir(base); len(entries) != 0 {
		t.Fatal("unused TLS created state")
	}
	conf.Global.APIPort = 9080
	first, err := prepareCertificates(conf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.Authority() == nil {
		t.Fatal("API-only configuration has no TLS identity")
	}
	fingerprint := first.Authority().Fingerprint()
	for _, enabled := range []bool{true, false} {
		conf.MITM.Enabled = enabled
		next, err := prepareCertificates(conf, first)
		if err != nil || next != first {
			t.Fatalf("MITM toggle replaced daemon identity: %v", err)
		}
		plugins, err := configurePlugins(conf, nil)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := loadMITM(t.Context(), conf, next.Authority(), http.DefaultClient, http.DefaultClient, plugins, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if enabled {
			if prepared.Host == nil || prepared.Host.Authority() != first.Authority() {
				t.Fatal("MITM did not borrow daemon CA")
			}
			prepared.Host.Close()
		} else if prepared.Host != nil {
			prepared.Host.Close()
			t.Fatal("API-only configuration created an interception host")
		}
	}
	restarted, err := prepareCertificates(conf, nil)
	if err != nil || restarted.Authority().Fingerprint() != fingerprint {
		t.Fatal("restart replaced CA", err)
	}
	conf.Global.APIPort = 0
	conf.MITM.Enabled = true
	if got, err := prepareCertificates(conf, first); err != nil || got != first {
		t.Fatal("MITM-only configuration lost identity", err)
	}
	conf.Certificate = config.Certificate{CACert: "absent.pem", CAKey: "absent.key"}
	if _, err := prepareCertificates(conf, first); err == nil {
		t.Fatal("explicit missing CA fell back to managed identity")
	}
	if _, err := os.Stat(filepath.Join(base, "absent.pem")); !os.IsNotExist(err) {
		t.Fatal("explicit missing CA was generated")
	}
	cert, key := filepath.Join(base, "custom.pem"), filepath.Join(base, "custom.key")
	if err := localca.Generate(cert, key, "custom CA", time.Hour); err != nil {
		t.Fatal(err)
	}
	conf.Certificate = config.Certificate{CACert: cert, CAKey: key}
	replacement, err := prepareCertificates(conf, first)
	if err != nil || replacement == first || replacement.Authority().Fingerprint() == fingerprint {
		t.Fatal("explicit CA replacement did not create a new identity", err)
	}
	managed, err := localca.Ensure(filepath.Join(base, localca.ManagedDirectory))
	if err != nil || managed.Fingerprint() != fingerprint {
		t.Fatal("explicit CA replacement changed managed store", err)
	}
}

func TestAPIOnlyHTTPSAndFailedCertificateReload(t *testing.T) {
	t.Setenv("DAE_LOCATION_CACHE", t.TempDir())
	server, err := apiserver.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	conf := mitmConfigForTest(t, "")
	conf.Global.APIPort = 9080
	certificates, err := prepareCertificates(conf, nil)
	if err != nil {
		t.Fatal(err)
	}
	app := &application{conf: conf, certificates: certificates, plane: &control.ControlPlane{}, managementAPI: server}
	app.publishAPI()
	root, err := localca.ReadCertificate(filepath.Join(os.Getenv("DAE_LOCATION_CACHE"), "pki", "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	tlsConfig := &tls.Config{RootCAs: roots}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: time.Second}
	defer client.CloseIdleConnections()
	page, err := client.Get("https://" + server.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	page.Body.Close()
	policy := page.Header.Get("Content-Security-Policy")
	if !strings.Contains(policy, "https://"+server.Addr().String()+"/api/certificate") || strings.Contains(policy, "/test/") {
		t.Fatalf("API-only page policy: %s", policy)
	}
	check := func() {
		t.Helper()
		response, err := client.Get("https://" + server.Addr().String() + "/api/certificate")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var certificate api.Certificate
		if err := json.UnmarshalRead(response.Body, &certificate); err != nil {
			t.Fatal(err)
		}
		if certificate.Fingerprint != certificates.Authority().Fingerprint() || certificate.MITMTestGeneration != "" || len(certificate.MITMTestOrigins) != 0 {
			t.Fatalf("API-only certificate: %+v", certificate)
		}
	}
	check()
	conn, err := tls.Dial("tcp", server.Addr().String(), tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Reload pauses the API before publishing; the same CA preserves TLS.
	app.managementAPI.SetHandler(nil)
	app.publishAPI()
	conn.SetDeadline(time.Now().Add(time.Second))
	fmt.Fprintf(conn, "GET /api/certificate HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", server.Addr())
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("same-CA publication invalidated TLS")
	}
	broken := *conf
	broken.Certificate = config.Certificate{CACert: "missing.pem", CAKey: "missing.key"}
	if _, err := app.apply(t.Context(), &broken, false, false, false); err == nil {
		t.Fatal("invalid certificate reload accepted")
	}
	if app.certificates != certificates || app.conf != conf {
		t.Fatal("rejected reload replaced active configuration")
	}
	check()
}
