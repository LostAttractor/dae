package tls

import (
	"context"
	cryptotls "crypto/tls"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type spiderRoundTrip func(*http.Request) (*http.Response, error)

func (f spiderRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type spiderBody struct {
	io.Reader
	closed bool
}

func (b *spiderBody) Close() error { b.closed = true; return nil }

type spiderEndlessReader struct{ read int }

func (r *spiderEndlessReader) Read(p []byte) (int, error) {
	clear(p)
	r.read += len(p)
	return len(p), nil
}

type spiderSlowReader struct{ ctx context.Context }

func (r spiderSlowReader) Read([]byte) (int, error) { <-r.ctx.Done(); return 0, r.ctx.Err() }

func newTestReality(t *testing.T, path string) *Reality {
	t.Helper()
	x, err := NewReality(testRealityURL(path), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { x.Close() })
	return x
}

func TestRealitySpiderValidParameters(t *testing.T) {
	x := newTestReality(t, "/search?p=8-16&c=2&t=3&i=10&r=0&query=keep")
	if x.spiderX != "/search?query=keep" || x.spider.padding != (realitySpiderRange{8, 16}) || x.spider.concurrency.min != 2 {
		t.Fatalf("unexpected spider configuration: %+v %s", x.spider, x.spiderX)
	}
	for _, path := range []string{"/bad%", "/?p=1&p=2", "/" + strings.Repeat("a", realitySpiderPathLimit)} {
		if _, err := NewReality(testRealityURL(path), nil); err == nil {
			t.Fatalf("accepted malformed path %q", path)
		}
	}
	for range 100 {
		value := randBetween(math.MinInt64, math.MaxInt64)
		if value == math.MaxInt64 {
			t.Fatal("range upper bound is exclusive")
		}
	}
}

func TestRealitySpiderBoundsAndClosesResponse(t *testing.T) {
	x := newTestReality(t, "/?c=8&t=8")
	endless := new(spiderEndlessReader)
	body := &spiderBody{Reader: endless}
	requests := 0
	client := &http.Client{Transport: spiderRoundTrip(func(r *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: 200, Body: body, Request: r}, nil
	})}
	x.crawlSpider(t.Context(), client)
	if endless.read != realitySpiderBodyLimit+1 || !body.closed || requests != 1 {
		t.Fatalf("unbounded/retained response: read=%d closed=%v requests=%d", endless.read, body.closed, requests)
	}
}

func TestRealitySpiderSlowResponseCancels(t *testing.T) {
	x := newTestReality(t, "/?c=8&t=8")
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	body := &spiderBody{Reader: spiderSlowReader{ctx}}
	client := &http.Client{Transport: spiderRoundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: body, Request: r}, nil
	})}
	x.crawlSpider(ctx, client)
	if !body.closed || ctx.Err() == nil {
		t.Fatal("slow stream not canceled and closed")
	}
}

func TestRealitySpiderNormalCrawl(t *testing.T) {
	x := newTestReality(t, "/?p=4&c=2&t=3")
	var requests, closes atomic.Int32
	client := &http.Client{Transport: spiderRoundTrip(func(r *http.Request) (*http.Response, error) {
		requests.Add(1)
		cookie, err := r.Cookie("padding")
		if err != nil || cookie.Value != "0000" {
			t.Errorf("incorrect padding: %v %v", cookie, err)
		}
		return &http.Response{StatusCode: 200, Body: &spiderCountedBody{Reader: strings.NewReader(`<a href="/next">next</a>`), closed: &closes}, Request: r}, nil
	})}
	x.crawlSpider(t.Context(), client)
	if requests.Load() != 7 || closes.Load() != 7 {
		t.Fatalf("requests=%d closed=%d", requests.Load(), closes.Load())
	}
}

type spiderCountedBody struct {
	io.Reader
	closed *atomic.Int32
}

func (b *spiderCountedBody) Close() error { b.closed.Add(1); return nil }

func TestRealitySpiderPathsAreBounded(t *testing.T) {
	paths := new(realitySpiderPaths)
	for i := range 1024 {
		paths.add("/" + strings.Repeat("a", 2000) + string(rune(0x1000+i)))
	}
	paths.add("/" + strings.Repeat("b", realitySpiderPathLimit))
	if len(paths.paths) == 0 || len(paths.paths) > realitySpiderPathCount || paths.bytes > realitySpiderPathBytes {
		t.Fatalf("unbounded paths: count=%d bytes=%d", len(paths.paths), paths.bytes)
	}
	for range 10 {
		if len(paths.choose()) > realitySpiderPathLimit {
			t.Fatal("oversized stored path")
		}
	}
}

func TestRealitySpiderCloseAndAdmission(t *testing.T) {
	// Pipe peers never read the HTTP/2 preface. Owner cancellation must interrupt
	// establishment as well as established requests, without waiting ten seconds.
	var owners []*Reality
	for range cap(realitySpiderSlots) {
		x := newTestReality(t, "/")
		client, peer := net.Pipe()
		t.Cleanup(func() { client.Close(); peer.Close() })
		if !x.startSpider(client) {
			t.Fatal("spider unexpectedly denied")
		}
		owners = append(owners, x)
	}
	extra := newTestReality(t, "/")
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	if extra.startSpider(conn) || owners[0].startSpider(conn) {
		t.Fatal("global or per-node budget exceeded")
	}
	done := make(chan struct{})
	go func() {
		for _, x := range owners {
			x.Close()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt blocked spider")
	}
	if len(realitySpiderSlots) != 0 {
		t.Fatal("spider slots leaked")
	}
	if owners[0].startSpider(conn) {
		t.Fatal("closed owner admitted work")
	}
}

func TestRealitySpiderHTTP2ClosesConnection(t *testing.T) {
	seen := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Error("spider did not use HTTP/2")
		}
		seen <- struct{}{}
		io.WriteString(w, "home")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	cfg := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	cfg.NextProtos = []string{"h2"}
	conn, err := cryptotls.Dial("tcp", server.Listener.Addr().String(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	x := newTestReality(t, "/")
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	x.runSpider(ctx, conn)
	select {
	case <-seen:
	default:
		t.Fatal("no HTTP/2 request")
	}
	if _, err := conn.Write([]byte("closed")); err == nil {
		t.Fatal("spider retained its connection")
	}
}

func TestRealitySpiderDeadlineReleasesResources(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		x := newTestReality(t, "/")
		conn, peer := net.Pipe()
		defer peer.Close()
		started := time.Now()
		if !x.startSpider(conn) {
			t.Fatal("spider unexpectedly denied")
		}
		x.spiderWorkers.Wait()
		if time.Since(started) != realitySpiderLifetime || len(realitySpiderSlots) != 0 {
			t.Fatal("spider did not release its slot at the deadline")
		}
		if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("deadline did not close connection: %v", err)
		}
	})
}
