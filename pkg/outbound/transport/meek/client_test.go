package meek

import (
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

// Close right after Write, as a session closing its carrier does, posts
// everything Write accepted.
func TestSessionClosePostsAcceptedBytes(t *testing.T) {
	for _, size := range []int{1 << 10, 64 << 10} {
		for range 20 {
			var received atomic.Int64
			s := newTestSession(t, func(_ http.ResponseWriter, r *http.Request) {
				n, _ := io.Copy(io.Discard, r.Body)
				received.Add(n)
			})
			if _, err := s.Write(make([]byte, size)); err != nil {
				t.Fatal(err)
			}
			_ = s.Close()
			if got := received.Load(); got != int64(size) {
				t.Fatalf("server received %d of %d bytes", got, size)
			}
		}
	}
}

func TestIdleSessionClosePostsNothing(t *testing.T) {
	var posts atomic.Int32
	s := newTestSession(t, func(http.ResponseWriter, *http.Request) { posts.Add(1) })
	start := time.Now()
	_ = s.Close()
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("Close took %v", waited)
	}
	if n := posts.Load(); n != 0 {
		t.Fatalf("closing an idle session sent %d POSTs", n)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A server that never answers holds Close for netproxy.CloseLinger.
func TestSessionCloseWaitIsBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var workers sync.WaitGroup
		s := newClientSession(t.Context(), roundTripFunc(func(r *http.Request) (*http.Response, error) {
			<-r.Context().Done()
			return nil, r.Context().Err()
		}), "https://meek.example/", &workers)
		if _, err := s.Write([]byte("tail")); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		_ = s.Close()
		if waited := time.Since(start); waited != netproxy.CloseLinger {
			t.Fatalf("Close took %v, want %v", waited, netproxy.CloseLinger)
		}
		workers.Wait()
	})
}

// An empty poll holds no accepted bytes: Close cancels it instead of waiting
// for a server that holds it.
func TestIdleSessionCloseCancelsPoll(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var workers sync.WaitGroup
		polling := make(chan struct{}, 1)
		s := newClientSession(t.Context(), roundTripFunc(func(r *http.Request) (*http.Response, error) {
			polling <- struct{}{}
			<-r.Context().Done()
			return nil, r.Context().Err()
		}), "https://meek.example/", &workers)
		<-polling
		start := time.Now()
		_ = s.Close()
		if waited := time.Since(start); waited != 0 {
			t.Fatalf("Close took %v", waited)
		}
		workers.Wait()
	})
}
