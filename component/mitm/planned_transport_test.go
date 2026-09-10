// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPlannedTransportClosesUnsentBody(t *testing.T) {
	for _, tc := range []struct {
		name   string
		plan   UpstreamPlanner
		closed bool
	}{
		{name: "missing planner"},
		{name: "planner failure", plan: func(*http.Request) (UpstreamPlan, error) {
			return UpstreamPlan{}, errors.New("no outbound available")
		}},
		{name: "incomplete plan", plan: func(*http.Request) (UpstreamPlan, error) {
			return UpstreamPlan{Key: "route"}, nil
		}},
		{name: "closed", plan: testUpstream((&net.Dialer{}).DialContext), closed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &plannedTransport{plan: tc.plan, closed: tc.closed}
			body := &replayCountedBody{Reader: strings.NewReader("upload")}
			r, _ := http.NewRequest("POST", "https://example.com/", body)
			if _, err := p.RoundTrip(r); err == nil {
				t.Fatal("forwarded without an available upstream plan")
			}
			if body.reads != 0 || body.closes != 1 {
				t.Fatalf("unsent body: read=%d closed=%d", body.reads, body.closes)
			}
		})
	}
}

func TestPlannedTransportConcurrentResponseCleanup(t *testing.T) {
	for _, evicted := range []bool{false, true} {
		t.Run(fmt.Sprintf("evicted=%t", evicted), func(t *testing.T) {
			for range 100 {
				var closes atomic.Int32
				pool := &routePool{refs: 2, used: 1} // Cache and an active response.
				p := &plannedTransport{
					pools: map[string]*routePool{"active": pool},
					owned: map[*routePool]func(){pool: func() { closes.Add(1) }},
				}
				if evicted {
					delete(p.pools, "active")
					if closePool := p.releaseLocked(pool); closePool != nil {
						t.Fatal("eviction closed an active response")
					}
				}
				// net/http permits Body.Close concurrently with Body.Read. An
				// empty body lets both reach the pool release at the same time.
				body := &plannedResponseBody{ReadCloser: http.NoBody, release: func() { p.release(pool) }}
				start := make(chan struct{})
				var done sync.WaitGroup
				for _, finish := range []func(){p.close, p.close, func() { _, _ = body.Read(make([]byte, 1)) }, func() { _ = body.Close() }} {
					done.Go(func() { <-start; finish() })
				}
				close(start)
				done.Wait()
				if got := closes.Load(); got != 1 {
					t.Fatalf("pool closed %d times", got)
				}
			}
		})
	}
}

func TestHTTP3PoolEvictionPreservesActiveResponses(t *testing.T) {
	authority, roots := http3TestAuthority(t)
	finish := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(finish) }) }
	defer release()
	upstream := http3TestUpstream(t, authority.TLSConfig("example.com"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/active" {
			fmt.Fprint(w, "before ")
			_ = http.NewResponseController(w).Flush()
			select {
			case <-finish:
			case <-r.Context().Done():
				return
			}
		}
		fmt.Fprint(w, "after")
	}))
	host := testHost(t, Options{UpstreamTLSConfig: &tls.Config{RootCAs: roots}})
	transport := host.plannedTransport(func(r *http.Request) (UpstreamPlan, error) {
		return UpstreamPlan{Key: r.URL.Path, DialPacket: func(ctx context.Context, _ string) (net.PacketConn, net.Addr, error) {
			conn, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp4", "127.0.0.1:0")
			return conn, upstream, err
		}}, nil
	}, true)
	defer transport.close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	request := func(path string) *http.Response {
		t.Helper()
		r, _ := http.NewRequestWithContext(ctx, "GET", "https://example.com/"+path, nil)
		response, err := transport.RoundTrip(r)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	active := request("active")
	defer active.Body.Close()
	// Each new route uses its own pool; the original active pool is retired.
	for i := range 33 {
		response := request(fmt.Sprint(i))
		_, err := io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	release()
	body, err := io.ReadAll(active.Body)
	if err != nil || string(body) != "before after" {
		t.Fatalf("eviction aborted an active stream: %q, %v", body, err)
	}
}

func TestPlannedTransportPreservesUpgradeBody(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buffer, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n")
		_ = buffer.Flush()
		_, _ = io.Copy(conn, conn)
	})}
	defer server.Close()
	go server.Serve(listener)
	host := testHost(t, Options{})
	transport := host.plannedTransport(testUpstream((&net.Dialer{}).DialContext), false)
	defer transport.close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, "GET", "http://"+listener.Addr().String(), nil)
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "test")
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, ok := response.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatal("upgrade body lost write access")
	}
	if _, err := io.Copy(body, strings.NewReader("echo")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 4)
	if _, err := io.ReadFull(body, data); err != nil || string(data) != "echo" {
		t.Fatalf("upgrade echo=%q, %v", data, err)
	}
}
