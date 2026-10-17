// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"syscall"
	"testing"
	"testing/synctest"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/prometheus/client_golang/prometheus"
)

func upstreamMetric(t *testing.T, name, id string) float64 {
	t.Helper()
	registry := prometheus.NewRegistry()
	registry.MustRegister(stats.DefaultStore)
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if label.GetName() == "id" && label.GetValue() == id {
					if metric.Histogram != nil {
						return float64(metric.Histogram.GetSampleCount())
					}
					return metric.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

func TestUDPDestinationRecordsEachEstablishedSocketOnce(t *testing.T) {
	source := netip.MustParseAddrPort("203.0.113.1:30000")
	endpoint, _ := resourceUDPEndpoint(t, source)
	endpoint.statsPath = stats.Path{NodeID: t.Name(), Outbound: "proxy", Network: common.NetworkUDP4}
	var pool UdpEndpointPool
	pool.add(source, endpoint)
	defer pool.closeAll()
	lock, _ := pool.UdpEndpointKeyLocker.Lock(source)
	defer pool.UdpEndpointKeyLocker.Unlock(source, lock)
	for _, destination := range []string{"192.0.2.1:443", "192.0.2.1:443", "192.0.2.2:443"} {
		if _, err := endpoint.socket(t.Context(), &pool, source, netip.MustParseAddrPort(destination)); err != nil {
			t.Fatal(err)
		}
	}
	if got := upstreamMetric(t, "dae_dial_duration_seconds", t.Name()); got != 2 {
		t.Fatalf("UDP dial samples = %v, want one per new socket", got)
	}
}

func TestUpstreamFailureIsRecordedOnceAcrossRelayHandling(t *testing.T) {
	upstream := upstreamDial{path: stats.Path{NodeID: t.Name(), Network: common.NetworkUDP4}}
	_, err := upstream.establishUpstream(t.Context(), func(context.Context) (io.Closer, error) {
		return nil, syscall.ECONNREFUSED
	})
	if !errors.Is(err, syscall.ECONNREFUSED) || netproxy.ClassifyFailure(err).Phase != netproxy.OpDial {
		t.Fatalf("lost dial failure: %v", err)
	}
	if !recordDataPlaneError(nil, upstream.path, fmt.Errorf("send packet: %w", err)) {
		t.Fatal("recorded failure lost its logging classification")
	}
	if got := upstreamMetric(t, "dae_path_errors_total", t.Name()); got != 1 {
		t.Fatalf("path failures = %v, want 1", got)
	}
	if got := upstreamMetric(t, "dae_dial_duration_seconds", t.Name()); got != 0 {
		t.Fatalf("failed setup recorded a successful dial: %v", got)
	}
}

func TestUpstreamClosesConnectionReturnedAfterTimeoutOrAbort(t *testing.T) {
	for _, abort := range []bool{false, true} {
		t.Run(fmt.Sprint(abort), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				lease := netproxy.NewLease(netproxy.NewResourceRef())
				upstream := upstreamDial{path: stats.Path{NodeID: t.Name()}, route: lease}
				conn := newCloseTrackingConn()
				want := error(context.DeadlineExceeded)
				if abort {
					want = errors.New("route replaced during setup")
				}
				result, err := upstream.establishUpstream(t.Context(), func(ctx context.Context) (io.Closer, error) {
					if abort {
						lease.Abort(want)
					} else {
						<-ctx.Done()
					}
					return conn, nil
				})
				if result != nil || !errors.Is(err, want) {
					t.Fatalf("late setup result = %v, %v; want %v", result, err, want)
				}
				synctest.Wait()
				select {
				case <-conn.closed:
				default:
					t.Fatal("late connection was not closed")
				}
				if got := upstreamMetric(t, "dae_dial_duration_seconds", t.Name()); got != 0 {
					t.Fatalf("aborted setup recorded a successful dial: %v", got)
				}
			})
		})
	}
}
