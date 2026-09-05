// SPDX-License-Identifier: AGPL-3.0-only

package surgemodule

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/mitmca"
)

func integrationEngine(t *testing.T, scripts map[string]string, upstreamTLS *tls.Config) (*Engine, *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	if err := mitmca.Generate(certPath, keyPath, "proxy integration CA", time.Hour); err != nil {
		t.Fatal(err)
	}
	authority, err := mitmca.Load(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := mitmca.ReadCertificate(certPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	runtime, err := NewRuntime(RuntimeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	moduleText := "[MITM]\nhostname=example.com\n[Script]\n"
	for _, kind := range []string{"http-request", "http-response"} {
		if _, ok := scripts[kind]; ok {
			moduleText += kind + " = type=" + kind + ",pattern=^https://example\\.com/,script-path=unused.js,requires-body=true\n"
		}
	}
	module, err := Parse(moduleText, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range module.Scripts {
		module.Scripts[i].Source = scripts[module.Scripts[i].Type]
	}
	engine, err := NewEngine(EngineOptions{
		Modules: []*Module{module}, Authority: authority, Runtime: runtime,
		MaxBodySize: 1 << 20, MaxConcurrentScripts: 4, ScriptTimeout: 2 * time.Second,
		UpstreamTLSConfig: upstreamTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	return engine, pool
}

func integrationClient(t *testing.T, engine *Engine, roots *x509.CertPool, dial DialContext, http2 bool) *http.Client {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var connections sync.Map
	var handlers sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Store(conn, struct{}{})
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				defer connections.Delete(conn)
				_ = engine.ServeConn(conn, "example.com", 443, dial)
			}()
		}
	}()
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
		},
		TLSClientConfig:   &tls.Config{RootCAs: roots},
		ForceAttemptHTTP2: http2, DisableCompression: true,
	}
	if !http2 {
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		_ = listener.Close()
		<-acceptDone
		connections.Range(func(key, _ any) bool {
			_ = key.(net.Conn).Close()
			return true
		})
		finished := make(chan struct{})
		go func() { handlers.Wait(); close(finished) }()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("intercepted connection did not close after client disconnect")
		}
	})
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func integrationUpstream(t *testing.T, handler http.Handler) (*httptest.Server, *tls.Config, DialContext) {
	t.Helper()
	upstream := httptest.NewUnstartedServer(handler)
	upstream.EnableHTTP2 = true
	upstream.Config.ErrorLog = log.New(io.Discard, "", 0)
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	trust := upstream.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	// The httptest certificate contains example.com and is trusted explicitly;
	// certificate verification remains enabled for the upstream TLS session.
	if trust.InsecureSkipVerify {
		t.Fatal("test upstream unexpectedly disables certificate verification")
	}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "example.com:443" {
			return nil, fmt.Errorf("unexpected upstream target %q", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
	}
	return upstream, trust, dial
}

func TestProxyIntegrationHTTP1AndHTTP2TLSRewrite(t *testing.T) {
	for _, useHTTP2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%t", useHTTP2), func(t *testing.T) {
			var upstreamCalls atomic.Int32
			_, trust, dial := integrationUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				data, err := io.ReadAll(r.Body)
				if err != nil || string(data) != "request-rewritten" || r.Header.Get("X-Request-Script") != "yes" || r.Host != "example.com" {
					t.Errorf("upstream received wrong request: body=%q host=%q header=%q err=%v", data, r.Host, r.Header.Get("X-Request-Script"), err)
				}
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("Content-Type", "text/plain")
				w.Header().Set("ETag", `"stale-original"`)
				w.Header().Set("Alt-Svc", `h3=":443"; ma=3600`)
				writer := gzip.NewWriter(w)
				_, _ = writer.Write([]byte("upstream:" + string(data)))
				_ = writer.Close()
			}))
			engine, roots := integrationEngine(t, map[string]string{
				"http-request":  `$done({headers:{...$request.headers,"X-Request-Script":"yes","Content-Length":"999"},body:"request-rewritten"})`,
				"http-response": `$done({headers:{...$response.headers,"X-Response-Script":"yes"},body:$response.body+":response-rewritten"})`,
			}, trust)
			client := integrationClient(t, engine, roots, dial, useHTTP2)
			for i := range 2 {
				response, err := client.Post("https://example.com/path", "text/plain", strings.NewReader("original"))
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil || string(body) != "upstream:request-rewritten:response-rewritten" || response.StatusCode != http.StatusOK {
					t.Fatalf("request %d response: %d %q %v", i, response.StatusCode, body, err)
				}
				wantProtocol := 1
				if useHTTP2 {
					wantProtocol = 2
				}
				if response.ProtoMajor != wantProtocol {
					t.Fatalf("client HTTP version %s, want major=%d", response.Proto, wantProtocol)
				}
				if response.Header.Get("X-Response-Script") != "yes" || response.Header.Get("Content-Encoding") != "" || response.Header.Get("ETag") != "" || response.Header.Get("Alt-Svc") != "" {
					t.Fatalf("response headers were not updated: %v", response.Header)
				}
				if response.ContentLength != int64(len(body)) {
					t.Fatalf("rewritten framing = %d, body has %d bytes", response.ContentLength, len(body))
				}
			}
			if upstreamCalls.Load() != 2 {
				t.Fatalf("upstream call count = %d", upstreamCalls.Load())
			}
		})
	}
}

func TestProxyIntegrationRejectsUntrustedUpstreamTLS(t *testing.T) {
	var upstreamCalls atomic.Int32
	_, _, dial := integrationUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		_, _ = io.WriteString(w, "must not reach untrusted upstream")
	}))
	engine, roots := integrationEngine(t, nil, &tls.Config{RootCAs: x509.NewCertPool()})
	client := integrationClient(t, engine, roots, dial, true)
	response, err := client.Get("https://example.com/untrusted")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadGateway || upstreamCalls.Load() != 0 {
		t.Fatalf("untrusted TLS reached application: status=%d calls=%d", response.StatusCode, upstreamCalls.Load())
	}
}

func TestProxyIntegrationRestrictsSNIAndRequestAuthority(t *testing.T) {
	var dialCalls atomic.Int32
	engine, roots := integrationEngine(t, nil, nil)
	dial := func(context.Context, string, string) (net.Conn, error) {
		dialCalls.Add(1)
		return nil, fmt.Errorf("unexpected upstream connection")
	}
	client := integrationClient(t, engine, roots, dial, true)
	if response, err := client.Get("https://different.example/"); err == nil {
		response.Body.Close()
		t.Fatal("TLS accepted SNI different from sniffed hostname")
	}
	request, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "different.example"
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusMisdirectedRequest || dialCalls.Load() != 0 {
		t.Fatalf("coalesced authority escaped MITM scope: status=%d dials=%d", response.StatusCode, dialCalls.Load())
	}
}

func TestProxyIntegrationScriptFailurePreservesCompressedBody(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = writer.Write([]byte("original response"))
	_ = writer.Close()
	_, trust, dial := integrationUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(compressed.Bytes())
	}))
	engine, roots := integrationEngine(t, map[string]string{"http-response": `throw Error("intentional script failure")`}, trust)
	client := integrationClient(t, engine, roots, dial, false)
	response, err := client.Get("https://example.com/failure")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "gzip" || !bytes.Equal(body, compressed.Bytes()) {
		t.Fatalf("script failure corrupted original response: status=%d body=%x err=%v", response.StatusCode, body, err)
	}
}

func TestProxyIntegrationBodylessResponses(t *testing.T) {
	for _, useHTTP2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%t", useHTTP2), func(t *testing.T) {
			_, trust, dial := integrationUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Encoding", "gzip")
				if r.URL.Path == "/204" {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				if r.URL.Path == "/304" {
					w.WriteHeader(http.StatusNotModified)
					return
				}
				writer := gzip.NewWriter(w)
				_, _ = writer.Write([]byte("original body"))
				_ = writer.Close()
			}))
			engine, roots := integrationEngine(t, map[string]string{
				"http-response": `
                  const headers = {...$response.headers,"X-Script":"ran"};
                  if($request.url.endsWith("/to204")) $done({status:204,headers});
                  else if($request.url.endsWith("/to304")) $done({status:304,headers});
                  else $done({headers});`,
			}, trust)
			client := integrationClient(t, engine, roots, dial, useHTTP2)
			for _, test := range []struct {
				method string
				path   string
				status int
			}{
				{http.MethodHead, "/head", http.StatusOK},
				{http.MethodGet, "/204", http.StatusNoContent},
				{http.MethodGet, "/304", http.StatusNotModified},
				{http.MethodGet, "/to204", http.StatusNoContent},
				{http.MethodGet, "/to304", http.StatusNotModified},
			} {
				request, err := http.NewRequest(test.method, "https://example.com"+test.path, nil)
				if err != nil {
					t.Fatal(err)
				}
				response, err := client.Do(request)
				if err != nil {
					t.Fatalf("%s %s: %v", test.method, test.path, err)
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil || response.StatusCode != test.status || len(body) != 0 || response.Header.Get("X-Script") != "ran" {
					t.Fatalf("%s %s: status=%d body=%q headers=%v err=%v", test.method, test.path, response.StatusCode, body, response.Header, err)
				}
			}
		})
	}
}
