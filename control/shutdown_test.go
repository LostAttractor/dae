// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/network"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/membuffer"
)

func newShutdownTestPlane(t *testing.T) *ControlPlane {
	t.Helper()
	ifmgr, err := network.NewInterfaceManager()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ifmgr.Close() })
	coreCtx, cancelCore := context.WithCancel(t.Context())
	t.Cleanup(cancelCore)
	plane := newLifecycleTestControlPlane(new(UdpEndpointPool))
	plane.core = &controlPlaneCore{closed: coreCtx, close: cancelCore, ifmgr: ifmgr}
	plane.deferFuncs = append(plane.deferFuncs, plane.dnsRelay.Close)
	t.Cleanup(func() {
		_ = plane.StopAndAbortConnections()
		_ = plane.Close()
	})
	return plane
}

func TestShutdownCancelsUDPBeforeDraining(t *testing.T) {
	plane := newShutdownTestPlane(t)
	plane.udpTaskPool.memory = membuffer.NewBudget(4096)
	conn := newDeadlineInterruptPacketConn()
	t.Cleanup(func() { close(conn.releaseClose) })
	src := testUdpKey(12007)
	dst := netip.MustParseAddrPort("192.0.2.1:443")
	endpoint := newUdpEndpoint(&UdpEndpointOptions{PacketConn: conn, NatTimeout: time.Hour})
	plane.udpEndpoints.add(src, endpoint)
	plane.enqueueUDPPacket([]byte("in-flight"), src, dst, nil)
	select {
	case <-conn.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("UDP write did not start")
	}
	plane.enqueueUDPPacket([]byte("queued"), src, dst, nil)
	closed := make(chan error, 1)
	go func() { closed <- errors.Join(plane.StopAndAbortConnections(), plane.Close()) }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown waited for the UDP deadline or blocking connection Close")
	}
	if used := plane.udpTaskPool.memory.Status().Used; used != 0 {
		t.Fatalf("shutdown retained %d bytes of queued packets", used)
	}
	if !plane.closedDone.Load() {
		t.Fatal("shutdown did not finish control-plane cleanup")
	}
}

type shutdownTCPConn struct {
	net.Conn
	close func() error
}

func (c *shutdownTCPConn) Close() error { return c.close() }

func TestShutdownInterruptsTrafficBeforeJoiningStateUsers(t *testing.T) {
	plane := newShutdownTestPlane(t)
	tcpStarted, tcpRelease := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(tcpRelease) })
	startTCP := sync.OnceFunc(func() { close(tcpStarted) })
	tcp := &shutdownTCPConn{Conn: newCloseTrackingConn(), close: func() error {
		startTCP()
		<-tcpRelease // A retired relay's Close must not hold up process teardown.
		return nil
	}}
	if !plane.tcpConnections.beginSetup(tcp) {
		t.Fatal("could not register TCP connection")
	}
	plane.tcpConnections.finishSetup()
	udp := newTestPacketConn(false)
	plane.udpEndpoints.add(testUdpKey(12008), newUdpEndpoint(&UdpEndpointOptions{PacketConn: udp, NatTimeout: time.Hour}))

	// DNS cleanup still owns plane state after observing cancellation.
	dnsCanceled, releaseDNS := make(chan struct{}), make(chan struct{})
	finishDNS := sync.OnceFunc(func() { close(releaseDNS) })
	t.Cleanup(finishDNS)
	if !plane.dnsRelay.admit() {
		t.Fatal("could not admit DNS work")
	}
	go func() {
		defer plane.dnsRelay.finish()
		<-plane.dnsRelay.ctx.Done()
		close(dnsCanceled)
		<-releaseDNS
	}()

	host, err := mitm.New(mitm.Options{DisableHTTP: true, DrainTimeout: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	plane.mitmHost = host
	mitmStarted, mitmCanceled := make(chan struct{}), make(chan struct{})
	go func() {
		_, _ = host.HandleDNS(t.Context(), &plugin.DNSExchange{}, func(ctx context.Context, _ *plugin.DNSExchange) (*plugin.DNSResponse, error) {
			close(mitmStarted)
			<-ctx.Done()
			close(mitmCanceled)
			return nil, ctx.Err()
		}, nil)
	}()
	<-mitmStarted
	kernelReleased := make(chan struct{})
	plane.core.addCleanup(func() error { close(kernelReleased); return nil })
	stopped := make(chan error, 1)
	go func() { stopped <- plane.StopAndAbortConnections() }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("aborting traffic waited for connection cleanup")
	}
	for name, interrupted := range map[string]<-chan struct{}{
		"TCP": tcpStarted, "UDP": udp.closed, "DNS": dnsCanceled, "MITM": mitmCanceled,
	} {
		select {
		case <-interrupted:
		case <-time.After(time.Second):
			t.Fatalf("%s waited for another component to drain", name)
		}
	}
	closed := make(chan error, 1)
	go func() { closed <- plane.Close() }()
	select {
	case <-kernelReleased:
		t.Fatal("kernel state released before DNS cleanup finished")
	case <-time.After(20 * time.Millisecond):
	}
	finishDNS()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown waited for a retired TCP connection or MITM grace period")
	}
	select {
	case <-kernelReleased:
	default:
		t.Fatal("shutdown skipped kernel cleanup")
	}
}

func TestRetireJoinsIngressAfterClosingAdmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		plane := newLifecycleTestControlPlane(new(UdpEndpointPool))
		plane.ingress = new(controlPlaneIngress)
		release := make(chan struct{})
		finish := sync.OnceFunc(func() { close(release) })
		t.Cleanup(finish)
		// A final socket read still owns plane state, but cannot admit new work.
		plane.ingress.loops.Go(func() { <-release })
		closed := make(chan error, 1)
		go func() { closed <- plane.retireTraffic() }()
		synctest.Wait()
		select {
		case <-closed:
			t.Fatal("retirement returned while ingress still owned shared state")
		default:
		}
		if emitUDPTask(plane.udpTaskPool, testUdpKey(12009), func() {}) {
			t.Fatal("retiring ingress admitted a late UDP task")
		}
		if plane.tcpConnections.beginSetup(newCloseTrackingConn()) {
			t.Fatal("retiring ingress admitted a late TCP setup")
		}
		finish()
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
	})
}
