// SPDX-License-Identifier: AGPL-3.0-only
package apiserver

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/api/client"
	"github.com/daeuniverse/dae/component/ca"
)

func TestClientCertificateProofAndProfile(t *testing.T) {
	authority, err := ca.Ensure(filepath.Join(t.TempDir(), "pki"))
	if err != nil {
		t.Fatal(err)
	}
	server, err := Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	server.Configure(NewHandler(Options{UserKey: "user", AdminKey: "admin", Pprof: true, Certificates: &Certificates{Identity: authority.Identity(), Handler: authority.Handler()}}), authority, t.TempDir())
	// Download locally without a key even when no TCP credentials exist.
	local, err := Listen("unix", filepath.Join(t.TempDir(), "api.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	local.SetHandler(NewHandler(Options{Pprof: true, Certificates: &Certificates{Identity: authority.Identity(), Handler: authority.Handler()}}))
	unix, err := client.New(client.Options{Endpoint: "unix://" + local.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close()
	var pem bytes.Buffer
	if err := unix.DownloadCertificate(t.Context(), "pem", &pem); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem.Bytes()) {
		t.Fatal("downloaded invalid CA")
	}
	user, err := client.New(client.Options{Endpoint: "https://" + server.Addr().String(), APIKey: "user", RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	defer user.Close()
	if _, err := user.VerifyCertificate(t.Context()); err != nil {
		t.Fatal("fresh client trust proof:", err)
	}
	if err := user.Profile(t.Context(), "heap", 0, io.Discard); err == nil {
		t.Fatal("user key could profile")
	}
	var profile bytes.Buffer
	if err := unix.Profile(t.Context(), "heap", 0, &profile); err != nil {
		t.Fatal(err)
	}
	decoded, err := gzip.NewReader(&profile)
	if err != nil {
		t.Fatal("profile not in standard gzip format:", err)
	}
	defer decoded.Close()
	if n, err := io.Copy(io.Discard, decoded); err != nil || n == 0 {
		t.Fatal("empty profile", err)
	}
	if _, err := client.New(client.Options{Endpoint: "http://" + server.Addr().String(), APIKey: "admin"}); err == nil {
		t.Fatal("HTTP credentials accepted")
	}
}

func TestCPUProfileDoesNotBlockPlaneReload(t *testing.T) {
	handler := NewHandler(Options{Pprof: true})
	server := &Server{handler: handler}
	started := make(chan struct{})
	recorder := &signalWriter{ResponseRecorder: httptest.NewRecorder(), started: started}
	request := httptest.NewRequest("GET", "http://unix/debug/pprof/profile?seconds=1", nil)
	request = request.WithContext(context.WithValue(t.Context(), http.LocalAddrContextKey, &net.UnixAddr{Net: "unix", Name: "api.sock"}))
	done := make(chan struct{})
	go func() { server.ServeHTTP(recorder, request); close(done) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("profile did not start")
	}
	drained := make(chan struct{})
	go func() {
		server.SetHandler(NewHandler(Options{Status: func() *api.StatusSnapshot { return &api.StatusSnapshot{} }}))
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("profile blocked reload")
	}
	<-done
	if recorder.Code != 200 || recorder.Body.Len() == 0 {
		t.Fatal("profile capture failed", recorder.Code)
	}
}

type signalWriter struct {
	*httptest.ResponseRecorder
	started chan struct{}
	once    sync.Once
}

func (w *signalWriter) Header() http.Header {
	w.once.Do(func() { close(w.started) })
	return w.ResponseRecorder.Header()
}
