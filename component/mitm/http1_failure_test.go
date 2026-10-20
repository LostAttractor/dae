// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
)

func TestHTTP1PendingUploadEarlyResponse(t *testing.T) {
	t.Parallel()
	for _, outcome := range []string{"reject", "reject-body", "reset", "reset-tls", "dial-failure", "plan-failure", "local", "authority"} {
		for _, framing := range []string{"small", "large", "chunked", "expect-continue"} {
			t.Run(outcome+"/"+framing, func(t *testing.T) {
				t.Parallel()
				authority, roots := http3TestAuthority(t)
				backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.HasPrefix(outcome, "reset") {
						if framing != "expect-continue" {
							var one [1]byte
							if _, err := io.ReadFull(r.Body, one[:]); err != nil {
								t.Error(err)
								return
							}
						}
						conn, _, err := http.NewResponseController(w).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						conn.Close()
						return
					}
					w.Header().Set("Connection", "close")
					if outcome == "reject-body" {
						w.Header().Set("Content-Length", "10")
						w.WriteHeader(http.StatusRequestEntityTooLarge)
						_, _ = io.WriteString(w, "early")
						_ = http.NewResponseController(w).Flush()
						time.Sleep(50 * time.Millisecond)
						_, _ = io.WriteString(w, "reply")
						return
					}
					w.Header().Set("Content-Length", "0")
					w.WriteHeader(http.StatusRequestEntityTooLarge)
				}))
				protocol := "http"
				if outcome == "reset-tls" {
					backend.TLS = authority.TLSConfig("example.com")
					backend.TLS.NextProtos = []string{"http/1.1"}
					backend.StartTLS()
					protocol = "https"
				} else {
					backend.Start()
				}
				defer backend.Close()
				plan := testUpstream(func(ctx context.Context, _, _ string) (net.Conn, error) {
					if outcome == "dial-failure" {
						return nil, errors.New("upstream offline")
					}
					return (&net.Dialer{}).DialContext(ctx, "tcp", backend.Listener.Addr().String())
				})
				if outcome == "plan-failure" {
					plan = func(*http.Request) (UpstreamPlan, error) { return UpstreamPlan{}, errors.New("no route") }
				}
				p := &testPlugin{plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: plugin.Scope{{Host: "example.com", Ports: []uint16{80}}}}}}, wrap: func(_ plugin.Flow, next plugin.Handler) plugin.Handler {
					return func(e *plugin.Exchange) (*http.Response, error) {
						if outcome == "local" {
							return &http.Response{StatusCode: 403, Header: make(http.Header), Body: http.NoBody}, nil
						}
						return next(e)
					}
				}}
				h := testHost(t, Options{Authority: authority, UpstreamTLSConfig: &tls.Config{RootCAs: roots}}, Instance{Plugin: p})
				client, served := tcpDrainClient(t, h, roots, protocol, plan)
				c, err := client.Transport.(*http.Transport).DialContext(t.Context(), "tcp", "example.com:80")
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				if protocol == "https" {
					c = tls.Client(c, &tls.Config{RootCAs: roots, ServerName: "example.com", NextProtos: []string{"http/1.1"}})
				}
				headers, prefix := "Content-Length: 6\r\n", "b"
				switch framing {
				case "large":
					headers = "Content-Length: 1000000\r\n"
				case "chunked":
					headers, prefix = "Transfer-Encoding: chunked\r\n", "6\r\nb"
					if strings.HasPrefix(outcome, "reset") {
						prefix = "1\r\nb\r\n"
					}
				case "expect-continue":
					headers, prefix = "Content-Length: 6\r\nExpect: 100-continue\r\n", ""
				}
				host := "example.com"
				if outcome == "authority" {
					host = "other.example"
				}
				if _, err := fmt.Fprintf(c, "POST / HTTP/1.1\r\nHost: %s\r\n%s\r\n%s", host, headers, prefix); err != nil {
					t.Fatal(err)
				}
				reader := bufio.NewReader(c)
				var response *http.Response
				for {
					response, err = http.ReadResponse(reader, nil)
					if err != nil {
						t.Fatalf("early response waited for upload: %v", err)
					}
					if response.StatusCode != 100 {
						break
					}
					response.Body.Close()
				}
				want := 413
				switch outcome {
				case "reset", "reset-tls", "dial-failure", "plan-failure":
					want = 502
				case "local":
					want = 403
				case "authority":
					want = 421
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || response.StatusCode != want {
					t.Fatalf("status=%d want=%d body=%q read=%v", response.StatusCode, want, body, err)
				}
				if outcome == "reject-body" && string(body) != "earlyreply" {
					t.Fatalf("truncated early response: %q", body)
				}
				// Cleanup must also finish while the client still holds the incomplete
				// upload open; returning headers alone would hide a blocked Body.Close.
				select {
				case <-served:
				case <-time.After(3 * time.Second):
					t.Fatal("handler retained incomplete upload")
				}
			})
		}
	}
}

func TestHTTP1UploadSurvivesUnusedConnectionFailure(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if r.Method == http.MethodPost && string(body) != "payload" {
			t.Errorf("retry upload=%q", body)
		}
		w.WriteHeader(204)
	}))
	defer backend.Close()
	host := testHost(t, Options{})
	transport := host.plannedTransport(testUpstream((&net.Dialer{}).DialContext), false)
	defer transport.close()
	warmup, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, backend.URL, nil)
	response, err := host.roundTrip(transport, warmup)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	var failed atomic.Bool
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		if info.Reused && failed.CompareAndSwap(false, true) {
			_ = info.Conn.Close()
		}
	}})
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, backend.URL, io.NopCloser(strings.NewReader("payload")))
	request.ContentLength = 7
	response, err = host.roundTrip(transport, request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 204 || !failed.Load() {
		t.Fatalf("status=%d injected failure=%t", response.StatusCode, failed.Load())
	}
}
