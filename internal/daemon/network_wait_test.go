// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/protocol/direct"
)

func setNetworkCheckLinks(t testing.TB, links ...string) {
	t.Helper()
	previous := CheckNetworkLinks
	CheckNetworkLinks = links
	t.Cleanup(func() { CheckNetworkLinks = previous })
}

func TestWaitForNetworkOnlineUsesReachableEndpoint(t *testing.T) {
	for _, stalled := range []bool{false, true} {
		name := "HTTP503"
		if stalled {
			name = "stalled"
		}
		t.Run(name, func(t *testing.T) {
			failedStarted := make(chan struct{})
			failedFinished := make(chan struct{})
			failed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(failedStarted)
				defer close(failedFinished)
				if stalled {
					<-r.Context().Done()
				} else {
					w.WriteHeader(http.StatusServiceUnavailable)
				}
			}))
			defer failed.Close()
			var reached atomic.Bool
			ready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-failedStarted:
				case <-r.Context().Done():
					return
				}
				reached.Store(true)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer ready.Close()
			setNetworkCheckLinks(t, failed.URL, ready.URL)
			// A failed endpoint's five-second retry must not consume this budget.
			if err := waitForNetworkOnline(t.Context(), time.Second, direct.NewDirectDialer(direct.Option{})); err != nil {
				t.Fatal(err)
			}
			if !reached.Load() {
				t.Fatal("network wait timed out before trying the reachable endpoint")
			}
			select {
			case <-failedFinished:
			case <-time.After(time.Second):
				t.Fatal("successful check did not cancel the stalled request")
			}
		})
	}
}

func TestWaitForNetworkOnlineCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var started atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if started.Add(1) == 3 {
			cancel()
		}
		<-r.Context().Done()
	}))
	defer server.Close()
	setNetworkCheckLinks(t, server.URL+"/1", server.URL+"/2", server.URL+"/3")
	if err := waitForNetworkOnline(ctx, time.Second, direct.NewDirectDialer(direct.Option{})); !errors.Is(err, context.Canceled) {
		t.Fatalf("parent cancellation = %v, want context canceled", err)
	}
}

func BenchmarkWaitForNetworkOnlineFailover(b *testing.B) {
	failed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer failed.Close()
	ready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(20 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ready.Close()
	setNetworkCheckLinks(b, failed.URL, ready.URL)
	b.ReportAllocs()
	for b.Loop() {
		if err := waitForNetworkOnline(b.Context(), startupNetworkWaitTimeout, direct.NewDirectDialer(direct.Option{})); err != nil {
			b.Fatal(err)
		}
	}
}
