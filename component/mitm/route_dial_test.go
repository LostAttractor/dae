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
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
)

func TestRouteFallbackUsesExistingConnection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer server.Close()
	var dials atomic.Int32
	var useFallbackOnly atomic.Bool
	fallback := UpstreamPlan{Key: "IPv4", Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		if dials.Add(1) > 1 {
			return nil, errors.New("new connection unavailable; existing connection is healthy")
		}
		return new(net.Dialer).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}}
	client, closeClient := NewRoutedHTTPClient(func(*http.Request) (UpstreamPlan, error) {
		if useFallbackOnly.Load() {
			return fallback, nil
		}
		return UpstreamPlan{Key: "IPv6", Dial: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("IPv6 unavailable") }, Next: func(context.Context) (UpstreamPlan, error) { return fallback, nil }}, nil
	})
	defer closeClient()
	client.Timeout = time.Second
	get := func() error {
		res, err := client.Get("http://same.example/")
		if err == nil {
			_, err = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
		}
		return err
	}
	if err := get(); err != nil {
		t.Fatal(err)
	}
	second := get()
	useFallbackOnly.Store(true)
	third := get()
	t.Logf("second dual-stack request: %v; direct pool check: %v; dials: %d", second, third, dials.Load())
	if second != nil {
		t.Errorf("fallback pool had a healthy connection but request failed: %v", second)
	}
	if third != nil {
		t.Errorf("existing pool control check failed: %v", third)
	}
	if dials.Load() != 1 {
		t.Fatalf("pool reuse opened %d connections", dials.Load())
	}
}

func TestHTTP3SharedFallbackDial(t *testing.T) {
	authority, roots := http3TestAuthority(t)
	upstream := http3TestUpstream(t, authority.TLSConfig("example.com"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	blackhole := http3TestPacketConn(t)
	var dials atomic.Int32
	plan := func(key string, peer net.Addr) UpstreamPlan {
		return UpstreamPlan{Key: key, DialPacket: func(ctx context.Context, _ string) (net.PacketConn, net.Addr, error) {
			dials.Add(1)
			conn, err := new(net.ListenConfig).ListenPacket(ctx, "udp4", "127.0.0.1:0")
			return conn, peer, err
		}}
	}
	host := testHost(t, Options{UpstreamTLSConfig: &tls.Config{RootCAs: roots}})
	transport := host.plannedTransport(func(*http.Request) (UpstreamPlan, error) {
		first := plan("IPv6", blackhole.LocalAddr())
		first.Next = func(context.Context) (UpstreamPlan, error) { return plan("IPv4", upstream), nil }
		return first, nil
	}, true)
	defer transport.close()
	ctx, cancel := context.WithTimeout(t.Context(), 450*time.Millisecond)
	defer cancel()
	start := make(chan struct{})
	var wg sync.WaitGroup
	var successes atomic.Int32
	for i := range 8 {
		wg.Go(func() {
			<-start
			begin := time.Now()
			request, _ := http.NewRequestWithContext(ctx, "GET", "https://example.com/", nil)
			response, err := transport.RoundTrip(request)
			if err == nil {
				_, err = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
			}
			t.Logf("request=%d elapsed=%s error=%v", i, time.Since(begin), err)
			if err == nil {
				successes.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	t.Logf("successes=%d packet dials=%d", successes.Load(), dials.Load())
	if successes.Load() != 8 {
		t.Errorf("healthy IPv4 HTTP/3 connection did not serve all concurrent requests")
	}
	if dials.Load() != 2 {
		t.Fatalf("shared selection opened %d packet sockets", dials.Load())
	}
}

type routeTestRoundTrip func(*http.Request) (*http.Response, error)

func (f routeTestRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHTTP3PreparedConnectionSurvivesPoolEviction(t *testing.T) {
	authority, roots := http3TestAuthority(t)
	var requests, dials atomic.Int32
	peer := http3TestUpstream(t, authority.TLSConfig("example.com"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		payload, err := io.ReadAll(r.Body)
		if err != nil || string(payload) != "once" {
			t.Errorf("payload=%q error=%v", payload, err)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	fallback := UpstreamPlan{Key: "IPv4", DialPacket: func(ctx context.Context, _ string) (net.PacketConn, net.Addr, error) {
		dials.Add(1)
		c, err := new(net.ListenConfig).ListenPacket(ctx, "udp4", "127.0.0.1:0")
		return c, peer, err
	}}
	first := UpstreamPlan{Key: "IPv6", DialPacket: func(context.Context, string) (net.PacketConn, net.Addr, error) {
		return nil, nil, errors.New("IPv6 unavailable")
	}, Next: func(context.Context) (UpstreamPlan, error) { return fallback, nil }}
	host := testHost(t, Options{UpstreamTLSConfig: &tls.Config{RootCAs: roots}})
	transport := host.plannedTransport(func(*http.Request) (UpstreamPlan, error) { return first, nil }, true)
	defer transport.close()
	firstPool, err := transport.acquire(first)
	if err != nil {
		t.Fatal(err)
	}
	transport.release(firstPool)
	original := firstPool.transport
	var prepared *quic.Conn
	firstPool.transport = routeTestRoundTrip(func(request *http.Request) (*http.Response, error) {
		response, err := original.RoundTrip(request)
		changed, ok := errors.AsType[*routeChanged](err)
		if !ok {
			return response, err
		}
		prepared = changed.pool.prepared[0].packet
		// Model other requests evicting the selected pool before this caller resumes.
		for i := range 33 {
			churn := fallback
			churn.Key = fmt.Sprintf("other-%d", i)
			pool, err := transport.acquire(churn)
			if err != nil {
				t.Fatal(err)
			}
			transport.release(pool)
		}
		replacement, acquireErr := transport.acquire(fallback)
		if acquireErr != nil {
			t.Fatal(acquireErr)
		}
		transport.release(replacement)
		if replacement == changed.pool {
			t.Fatal("selected pool was not evicted")
		}
		return response, err
	})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	body := &replayCountedBody{Reader: strings.NewReader("once")}
	request, _ := http.NewRequestWithContext(ctx, "POST", "https://example.com/", body)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	if prepared == nil || prepared.Context().Err() != nil {
		t.Fatal("handoff closed the successful connection")
	}
	payload, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || string(payload) != "ok" || dials.Load() != 1 || requests.Load() != 1 || body.closes != 1 {
		t.Fatalf("body=%q error=%v dials=%d requests=%d body closes=%d", payload, err, dials.Load(), requests.Load(), body.closes)
	}
}

func TestRouteEmptyFallbackPoolRediscoversBeforeSending(t *testing.T) {
	var requests, plans, dials atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		payload, err := io.ReadAll(r.Body)
		if err != nil || string(payload) != "once" {
			t.Errorf("payload=%q error=%v", payload, err)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	fallback := UpstreamPlan{Key: "IPv4", Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		dials.Add(1)
		return new(net.Dialer).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}}
	transport := new(Host).plannedTransport(func(*http.Request) (UpstreamPlan, error) {
		plans.Add(1)
		return UpstreamPlan{Key: "IPv6", Dial: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unreachable") }, Next: func(context.Context) (UpstreamPlan, error) { return fallback, nil }}, nil
	}, false)
	defer transport.close()
	empty, err := transport.acquire(fallback)
	if err != nil {
		t.Fatal(err)
	}
	transport.release(empty)
	body := &replayCountedBody{Reader: strings.NewReader("once")}
	request, _ := http.NewRequestWithContext(t.Context(), "POST", "http://example.com/", body)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if requests.Load() != 1 || dials.Load() != 1 || plans.Load() != 2 || body.closes != 1 {
		t.Fatalf("requests=%d dials=%d plans=%d body closes=%d", requests.Load(), dials.Load(), plans.Load(), body.closes)
	}
}

func TestRouteFallbackPreservesNativeRequestRetry(t *testing.T) {
	for _, packet := range []bool{false, true} {
		t.Run(fmt.Sprintf("HTTP3=%t", packet), func(t *testing.T) {
			authority, roots := http3TestAuthority(t)
			fallback := UpstreamPlan{Key: "IPv4"}
			first := UpstreamPlan{Key: "IPv6"}
			var attempts *atomic.Int32
			if packet {
				var peer net.Addr
				peer, attempts = retryTestHTTP3Peer(t, authority.TLSConfig("example.com"), http3.ErrCodeRequestRejected, "payload")
				fallback.DialPacket = func(ctx context.Context, _ string) (net.PacketConn, net.Addr, error) {
					conn, err := new(net.ListenConfig).ListenPacket(ctx, "udp4", "127.0.0.1:0")
					return conn, peer, err
				}
				first.DialPacket = func(context.Context, string) (net.PacketConn, net.Addr, error) {
					return nil, nil, errors.New("unreachable")
				}
			} else {
				var address string
				address, attempts = retryTestPeer(t, authority.TLSConfig("example.com"), "GOAWAY", "payload")
				fallback.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
					return new(net.Dialer).DialContext(ctx, "tcp", address)
				}
				first.Dial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unreachable") }
			}
			first.Next = func(context.Context) (UpstreamPlan, error) { return fallback, nil }
			host := testHost(t, Options{UpstreamTLSConfig: &tls.Config{RootCAs: roots}})
			transport := host.plannedTransport(func(*http.Request) (UpstreamPlan, error) { return first, nil }, packet)
			defer transport.close()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			request, _ := http.NewRequestWithContext(ctx, "POST", "https://example.com/", strings.NewReader("payload"))
			response, err := transport.RoundTrip(request)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode >= 300 || attempts.Load() != 2 {
				t.Fatalf("status=%d attempts=%d", response.StatusCode, attempts.Load())
			}
		})
	}
}

type preparedTestConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *preparedTestConn) Close() error { c.closes.Add(1); return c.Conn.Close() }

func TestPreparedRouteCleanup(t *testing.T) {
	for _, closeTransport := range []bool{false, true} {
		t.Run(fmt.Sprint(closeTransport), func(t *testing.T) {
			local, remote := net.Pipe()
			defer remote.Close()
			conn := &preparedTestConn{Conn: local}
			fallback := UpstreamPlan{Key: "IPv4", Dial: func(context.Context, string, string) (net.Conn, error) { return conn, nil }}
			first := UpstreamPlan{Key: "IPv6", Dial: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unreachable") }, Next: func(context.Context) (UpstreamPlan, error) { return fallback, nil }}
			transport := new(Host).plannedTransport(nil, false)
			defer transport.close()
			initial, err := transport.acquire(first)
			if err != nil {
				t.Fatal(err)
			}
			selection := newRouteDial(t.Context(), first, nil)
			_, err = selection.connect(t.Context(), transport, initial, func(ctx context.Context, pool *routePool) (*connectedRoute, error) {
				c, err := pool.plan.Dial(ctx, "tcp", "example.com:80")
				return &connectedRoute{pool: pool, stream: c}, err
			})
			transport.release(initial)
			if _, ok := errors.AsType[*routeChanged](err); !ok {
				t.Fatalf("selection=%v", err)
			}
			if closeTransport {
				transport.close()
			}
			selection.close(transport)
			if conn.closes.Load() != 1 {
				t.Fatalf("unused prepared connection closed %d times", conn.closes.Load())
			}
		})
	}
}

func TestHTTP3EvictedDialCancellation(t *testing.T) {
	started, finishDial := make(chan struct{}), make(chan struct{})
	allowDialReturn := sync.OnceFunc(func() { close(finishDial) })
	defer allowDialReturn()
	first := UpstreamPlan{Key: "first", DialPacket: func(ctx context.Context, _ string) (net.PacketConn, net.Addr, error) {
		close(started)
		<-ctx.Done()
		<-finishDial
		return nil, nil, ctx.Err()
	}, Next: func(ctx context.Context) (UpstreamPlan, error) {
		<-ctx.Done()
		return UpstreamPlan{}, io.EOF
	}}
	transport := new(Host).plannedTransport(func(*http.Request) (UpstreamPlan, error) { return first, nil }, true)
	pool, err := transport.acquire(first)
	if err != nil {
		t.Fatal(err)
	}
	transport.release(pool)
	original := pool.transport
	cleanupStarted := make(chan struct{})
	pool.transport = routeTestRoundTrip(func(request *http.Request) (*http.Response, error) {
		selection := request.Context().Value(routeDialKey{}).(*routeDial)
		cancel := selection.cancel
		selection.cancel = func() { cancel(); close(cleanupStarted) }
		return original.RoundTrip(request)
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, "GET", "https://example.com/", nil)
	done := make(chan error, 1)
	go func() { _, err := transport.RoundTrip(request); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("packet dial did not start")
	}
	for i := range 33 {
		plan := first
		plan.Key = fmt.Sprintf("other-%d", i)
		other, err := transport.acquire(plan)
		if err != nil {
			t.Fatal(err)
		}
		transport.release(other)
	}
	cancel()
	// Return from the packet dial only after RoundTrip begins cleaning up its
	// selection, when releasing the request's pool lease early would deadlock.
	select {
	case <-cleanupStarted:
	case <-time.After(time.Second):
		t.Fatal("request cancellation did not start selection cleanup")
	}
	allowDialReturn()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled request returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("evicted HTTP/3 dial deadlocked during cancellation")
	}
	transport.mu.Lock()
	refs, owned := pool.refs, transport.owned[pool] != nil
	transport.mu.Unlock()
	transport.close()
	if refs != 0 || owned {
		t.Fatalf("evicted pool was not released: refs=%d owned=%t", refs, owned)
	}
}
