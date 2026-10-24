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
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

func TestHTTP1PendingUploadEarlyResponse(t *testing.T) {
	t.Parallel()
	for _, outcome := range []string{"reject", "reject-body", "reject-body-tls", "reset", "reset-tls", "dial-failure", "plan-failure", "local", "authority"} {
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
					if strings.HasPrefix(outcome, "reject-body") {
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
				if strings.HasSuffix(outcome, "-tls") {
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
				if strings.HasPrefix(outcome, "reject-body") && string(body) != "earlyreply" {
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

// Keep the first underlying Read, final downstream headers and response tail
// separate: a zero ExpectContinueTimeout can start the transport writer before
// the server's expectContinueReader has been read even once.
func TestHTTP1ExpectContinueResponseOrdering(t *testing.T) {
	t.Parallel()
	for _, scenario := range []string{"response-first", "read-first", "canceled-response"} {
		t.Run(scenario, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				readStarted := make(chan struct{})
				allowRead := make(chan struct{})
				readResult := make(chan error, 1)
				allowResponse := make(chan struct{})
				finalHeader := make(chan struct{})
				allowTail := make(chan struct{})
				upstreamClosed := make(chan struct{})
				h := testHost(t, Options{})
				upstream, peer := net.Pipe()
				defer peer.Close()
				defer upstream.Close()
				go func() {
					request, err := http.ReadRequest(bufio.NewReader(peer))
					if err != nil {
						t.Errorf("upstream headers: %v", err)
						return
					}
					if request.Header.Get("Expect") != "100-continue" {
						t.Error("upstream request lost Expect")
					}
					<-allowResponse
					_, _ = io.WriteString(peer, "HTTP/1.1 413 Request Entity Too Large\r\nContent-Length: 10\r\nConnection: close\r\n\r\nearly")
					<-allowTail
					_, _ = io.WriteString(peer, "reply")
				}()
				handler, cleanup := h.Handler("http", "example.com", 80, testUpstream(func(context.Context, string, string) (net.Conn, error) {
					return &closeObservedConn{Conn: upstream, closed: sync.OnceFunc(func() { close(upstreamClosed) })}, nil
				}))
				defer cleanup()
				served := make(chan struct{})
				connectionClosed := make(chan struct{})
				server := &http.Server{ConnState: func(_ net.Conn, state http.ConnState) {
					if state == http.StateClosed {
						close(connectionClosed)
					}
				}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer close(served)
					r.Body = &firstReadGate{ReadCloser: r.Body, beforeRead: sync.OnceFunc(func() { close(readStarted); <-allowRead }), result: readResult}
					handler.ServeHTTP(&finalHeaderObserver{ResponseWriter: w, written: finalHeader}, r)
				})}
				client, ingress := net.Pipe()
				defer client.Close()
				defer server.Close()
				listener := &singleConnListener{Conn: ingress, done: make(chan struct{}), finished: make(chan struct{})}
				go server.Serve(listener)
				if _, err := io.WriteString(client, "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\nExpect: 100-continue\r\n\r\n"); err != nil {
					t.Fatal(err)
				}
				continued := make(chan struct{})
				type result struct {
					status int
					body   string
					err    error
				}
				responseResult := make(chan result, 1)
				go func() {
					reader := bufio.NewReader(client)
					for {
						response, err := http.ReadResponse(reader, nil)
						if err != nil {
							responseResult <- result{err: err}
							return
						}
						if response.StatusCode == http.StatusContinue {
							response.Body.Close()
							close(continued)
							continue
						}
						body, err := io.ReadAll(response.Body)
						response.Body.Close()
						responseResult <- result{status: response.StatusCode, body: string(body), err: err}
						return
					}
				}()
				<-readStarted // The transport's continue timeout has already elapsed.
				if scenario == "read-first" {
					close(allowRead)
					<-continued // The server has entered expectContinueReader.Read.
				}
				close(allowResponse)
				<-finalHeader // WriteHeader has disabled the unstarted Expect reader.
				if scenario != "read-first" {
					close(allowRead)
					if err := <-readResult; !errors.Is(err, http.ErrBodyReadAfterClose) {
						t.Fatalf("first underlying body Read = %v", err)
					}
				}
				synctest.Wait()
				closedBeforeTail := false
				select {
				case <-upstreamClosed:
					closedBeforeTail = true
				default:
				}
				if scenario == "canceled-response" {
					h.forceCancel()
				} else {
					close(allowTail)
				}
				got := <-responseResult
				<-served // The client has never sent or closed its upload.
				<-connectionClosed
				if scenario == "canceled-response" {
					<-upstreamClosed
					close(allowTail)
					if closedBeforeTail || got.err == nil {
						t.Fatalf("closed before cancel=%t; client error=%v", closedBeforeTail, got.err)
					}
					return
				}
				if closedBeforeTail || got.err != nil || got.status != 413 || got.body != "earlyreply" {
					t.Fatalf("upstream closed before tail=%t; status=%d body=%q client error=%v", closedBeforeTail, got.status, got.body, got.err)
				}
			})
		})
	}
}

func TestHTTP1ExpectContinueLocalEcho(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		p := &testPlugin{
			plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: plugin.Scope{{Host: "example.com", Ports: []uint16{80}}}}}},
			wrap: func(_ plugin.Flow, _ plugin.Handler) plugin.Handler {
				return func(e *plugin.Exchange) (*http.Response, error) {
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: e.Request.Body, ContentLength: -1}, nil
				}
			},
		}
		authority, _ := http3TestAuthority(t)
		h := testHost(t, Options{Authority: authority}, Instance{Plugin: p})
		handler, cleanup := h.Handler("http", "example.com", 80, func(*http.Request) (UpstreamPlan, error) {
			t.Error("local response attempted an upstream request")
			return UpstreamPlan{}, errors.New("unexpected upstream request")
		})
		defer cleanup()
		served := make(chan struct{})
		finalHeader := make(chan struct{})
		readResult := make(chan error, 1)
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer close(served)
			r.Body = &firstReadGate{ReadCloser: r.Body, beforeRead: func() {}, result: readResult}
			handler.ServeHTTP(&finalHeaderObserver{ResponseWriter: w, written: finalHeader}, r)
		})}
		client, ingress := net.Pipe()
		defer client.Close()
		defer server.Close()
		listener := &singleConnListener{Conn: ingress, done: make(chan struct{}), finished: make(chan struct{})}
		go server.Serve(listener)
		if _, err := io.WriteString(client, "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\nExpect: 100-continue\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		responseDone := make(chan struct{})
		go func() {
			defer close(responseDone)
			response, err := http.ReadResponse(bufio.NewReader(client), nil)
			if err != nil {
				// ReverseProxy may abort before its asynchronous header flush runs.
				if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Errorf("local response headers: %v", err)
				}
				return
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Errorf("local response status = %d", response.StatusCode)
			}
			if _, err := io.ReadAll(response.Body); err == nil {
				t.Error("closed Expect reader should abort the local streaming response")
			}
		}()
		<-finalHeader
		if err := <-readResult; !errors.Is(err, http.ErrBodyReadAfterClose) {
			t.Errorf("local response body Read = %v", err)
		}
		synctest.Wait()
		select {
		case <-served:
		default:
			t.Error("local echo waited for its own response to finish before returning its body-read error")
			h.forceCancel() // Release a failing implementation without closing the client upload.
		}
		<-served
		<-responseDone
	})
}

type firstReadGate struct {
	io.ReadCloser
	beforeRead func()
	result     chan<- error
}

func (b *firstReadGate) Read(p []byte) (int, error) {
	b.beforeRead()
	n, err := b.ReadCloser.Read(p)
	b.result <- err
	return n, err
}

type finalHeaderObserver struct {
	http.ResponseWriter
	written chan struct{}
}

func (w *finalHeaderObserver) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *finalHeaderObserver) WriteHeader(status int) {
	w.ResponseWriter.WriteHeader(status)
	if status >= 200 {
		close(w.written)
	}
}

type closeObservedConn struct {
	net.Conn
	closed func()
}

func (c *closeObservedConn) Close() error {
	err := c.Conn.Close()
	c.closed()
	return err
}

func TestHTTP1RequestBodyErrorLifetime(t *testing.T) {
	t.Parallel()
	for _, started := range []bool{false, true} {
		for _, readErr := range []error{http.ErrBodyReadAfterClose, io.ErrUnexpectedEOF, io.EOF} {
			t.Run(fmt.Sprintf("response=%t/%v", started, readErr), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					readDone := make(chan struct{})
					body := &http1RequestBody{
						ReadCloser: &closeWaitsForRead{ReadCloser: failedRequestBody{err: readErr}, readDone: readDone},
						deadline:   func(time.Time) error { return nil },
						done:       make(chan struct{}),
					}
					body.responseStarted.Store(started)
					go func() {
						defer close(readDone)
						_, err := body.Read(make([]byte, 1))
						if !errors.Is(err, readErr) {
							t.Errorf("Read = %v, want %v", err, readErr)
						}
					}()
					synctest.Wait()
					select {
					case <-readDone:
					default:
						t.Error("ordinary request reader held an error for its response")
					}
					// A Close that joins its reader must release the error first.
					if err := body.Close(); err != nil {
						t.Fatal(err)
					}
					<-readDone
				})
			})
		}
	}
}

func TestHTTPUploadBodyErrorLifetime(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, protocol, finish string
		responseStarted        bool
		readErr                error
		wantWait               bool
	}{
		{"transport close", "http1", "transport", true, http.ErrBodyReadAfterClose, true},
		{"request close", "http1", "request", true, http.ErrBodyReadAfterClose, true},
		{"connection close", "http1", "connection", true, http.ErrBodyReadAfterClose, true},
		{"http2", "http2", "transport", true, http.ErrBodyReadAfterClose, false},
		{"auxiliary", "auxiliary", "transport", true, http.ErrBodyReadAfterClose, false},
		{"before response", "http1", "transport", false, http.ErrBodyReadAfterClose, false},
		{"unexpected EOF", "http1", "transport", true, io.ErrUnexpectedEOF, false},
		{"EOF", "http1", "transport", true, io.EOF, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				readDone := make(chan struct{})
				source := &http1RequestBody{
					ReadCloser: failedRequestBody{err: test.readErr},
					deadline:   func(time.Time) error { return nil },
					done:       make(chan struct{}),
				}
				source.responseStarted.Store(test.responseStarted)
				conn, cancel := context.WithCancel(t.Context())
				defer cancel()
				body := &httpUploadBody{
					ReadCloser: &closeWaitsForRead{ReadCloser: source, readDone: readDone},
					conn:       conn, requestBody: source, done: make(chan struct{}),
				}
				if test.protocol == "http2" {
					body.conn = nil
				}
				if test.protocol == "auxiliary" {
					body.requestBody = nil
				}
				go func() {
					defer close(readDone)
					_, err := body.Read(make([]byte, 1))
					if !errors.Is(err, test.readErr) {
						t.Errorf("Read = %v, want %v", err, test.readErr)
					}
				}()
				synctest.Wait()
				select {
				case <-readDone:
					if test.wantWait {
						t.Error("HTTP/1 upload error escaped before response finished")
					}
				default:
					if !test.wantWait {
						t.Error("unrelated upload error held for a response")
					}
				}
				switch test.finish {
				case "transport":
					_ = body.Close()
				case "request":
					_ = source.Close()
				case "connection":
					cancel()
				}
				<-readDone
				_ = body.Close()
			})
		})
	}
}

type closeWaitsForRead struct {
	io.ReadCloser
	readDone <-chan struct{}
}

func (b *closeWaitsForRead) Close() error {
	<-b.readDone
	return b.ReadCloser.Close()
}

func TestHTTPUpgradeHalfClose(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, first := range []string{"client", "upstream"} {
			t.Run(fmt.Sprintf("tls=%t/%s-first", encrypted, first), func(t *testing.T) {
				authority, roots := http3TestAuthority(t)
				finished := make(chan error, 1)
				backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					c, rw, err := http.NewResponseController(w).Hijack()
					if err != nil {
						finished <- err
						return
					}
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(3 * time.Second))
					_, err = io.WriteString(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n")
					if err == nil {
						err = rw.Flush()
					}
					if err != nil {
						finished <- err
						return
					}
					if first == "upstream" {
						_, err = io.WriteString(c, "prefix")
						if err == nil {
							err = netproxy.CloseWrite(c)
						}
						if err != nil {
							finished <- err
							return
						}
					}
					body, err := io.ReadAll(rw)
					if err == nil && string(body) != "payload" {
						err = fmt.Errorf("upload=%q", body)
					}
					if err == nil && first == "client" {
						_, err = fmt.Fprintf(c, "ack:%s", body)
					}
					finished <- err
				}))
				backend.TLS = authority.TLSConfig("example.com")
				if encrypted {
					backend.StartTLS()
				} else {
					backend.Start()
				}
				defer backend.Close()
				h := testHost(t, Options{Authority: authority, UpstreamTLSConfig: &tls.Config{RootCAs: roots}})
				protocol := "http"
				if encrypted {
					protocol = "https"
				}
				client, _ := tcpDrainClient(t, h, roots, protocol, testUpstream(func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "tcp", backend.Listener.Addr().String())
				}))
				c, err := client.Transport.(*http.Transport).DialContext(t.Context(), "tcp", "example.com:80")
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				if encrypted {
					c = tls.Client(c, &tls.Config{RootCAs: roots, ServerName: "example.com", NextProtos: []string{"http/1.1"}})
				}
				if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n"); err != nil {
					t.Fatal(err)
				}
				reader := bufio.NewReader(c)
				resp, err := http.ReadResponse(reader, nil)
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != 101 {
					t.Fatalf("upgrade status=%d", resp.StatusCode)
				}
				if first == "upstream" {
					body, err := io.ReadAll(reader)
					if err != nil || string(body) != "prefix" {
						t.Fatalf("response=%q read=%v", body, err)
					}
				}
				if _, err := io.WriteString(c, "payload"); err != nil {
					t.Fatal(err)
				}
				if err := netproxy.CloseWrite(c); err != nil {
					t.Fatal(err)
				}
				if first == "client" {
					body, err := io.ReadAll(reader)
					if err != nil || string(body) != "ack:payload" {
						t.Fatalf("trailing response=%q read=%v", body, err)
					}
				}
				if err := <-finished; err != nil {
					t.Fatal(err)
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
