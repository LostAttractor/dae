// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

type lifetimeTransport struct {
	closed atomic.Int32
}

func (*lifetimeTransport) DialContext(context.Context, string, string) (net.Conn, error) {
	conn, peer := net.Pipe()
	_ = peer.Close()
	return conn, nil
}

func (*lifetimeTransport) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func (d *lifetimeTransport) Close() error {
	d.closed.Add(1)
	return nil
}

func newLifetimeDialer(t *testing.T) (*Dialer, *lifetimeTransport) {
	t.Helper()
	transport := new(lifetimeTransport)
	runtime := netproxy.NewRuntime(netproxy.Layer{Data: transport, Resources: []io.Closer{transport}})
	dialer := NewDialer(runtime, &GlobalOption{}, &Property{Name: t.Name(), Link: "test://" + t.Name()}, false, "")
	t.Cleanup(func() { _ = dialer.Close() })
	return dialer, transport
}

func assertLifetimeDial(t *testing.T, d *Dialer) net.Conn {
	t.Helper()
	conn, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("retained runtime rejected a new upstream connection: %v", err)
	}
	return conn
}

func assertLifetimeRetired(t *testing.T, d *Dialer, transport *lifetimeTransport) {
	t.Helper()
	if conn, err := d.DialContext(context.Background(), "tcp", "example.com:443"); !errors.Is(err, net.ErrClosed) {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("retired runtime accepted new work: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := d.runtime.Wait(ctx); err != nil {
		t.Fatalf("runtime cleanup did not finish: %v", err)
	}
	if transport.closed.Load() != 1 {
		t.Fatalf("owned transport closed %d times", transport.closed.Load())
	}
}

func TestDialerRetainAllowsUpstreamRequestsAfterClose(t *testing.T) {
	d, transport := newLifetimeDialer(t)
	release, err := d.Retain()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	checksFinished := make(chan struct{})
	d.checkWG.Go(func() {
		<-d.ctx.Done()
		close(checksFinished)
	})
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-checksFinished:
	default:
		t.Fatal("Close returned before health-check worker stopped")
	}
	if d.ctx.Err() == nil {
		t.Fatal("Close did not cancel health checking")
	}
	if newRelease, err := d.Retain(); !errors.Is(err, net.ErrClosed) || newRelease != nil {
		t.Fatalf("accepted a retain after Close: %v", err)
	}
	conn := assertLifetimeDial(t, d)
	if transport.closed.Load() != 0 {
		t.Fatal("Close released the runtime while a caller retained it")
	}
	release()
	if next, err := d.DialContext(context.Background(), "tcp", "example.com:443"); !errors.Is(err, net.ErrClosed) {
		if next != nil {
			next.Close()
		}
		t.Fatalf("release did not retire the runtime: %v", err)
	}
	if transport.closed.Load() != 0 {
		t.Fatal("release closed resources before an established upstream connection drained")
	}
	_ = conn.Close()
	assertLifetimeRetired(t, d, transport)
	release()
}

func TestDialerRetainMultipleAndReleaseBeforeClose(t *testing.T) {
	d, transport := newLifetimeDialer(t)
	first, err := d.Retain()
	if err != nil {
		t.Fatal(err)
	}
	defer first()
	second, err := d.Retain()
	if err != nil {
		t.Fatal(err)
	}
	defer second()
	first()
	first()
	_ = assertLifetimeDial(t, d).Close()
	_ = d.Close()
	_ = assertLifetimeDial(t, d).Close()
	second()
	second()
	assertLifetimeRetired(t, d, transport)
}

func TestDialerCloseWithoutRetainsStillRetiresImmediately(t *testing.T) {
	d, transport := newLifetimeDialer(t)
	_ = d.Close()
	_ = d.Close()
	assertLifetimeRetired(t, d, transport)
}

func TestDialerRetainReleasedBeforeCloseDoesNotRetire(t *testing.T) {
	d, transport := newLifetimeDialer(t)
	release, err := d.Retain()
	if err != nil {
		t.Fatal(err)
	}
	release()
	release()
	_ = assertLifetimeDial(t, d).Close()
	if transport.closed.Load() != 0 {
		t.Fatal("last release retired a dialer before Close")
	}
	_ = d.Close()
	assertLifetimeRetired(t, d, transport)
}

func TestDialerRetainReleaseConcurrentWithClose(t *testing.T) {
	for range 32 {
		d, transport := newLifetimeDialer(t)
		const count = 8
		releases := make([]func(), count)
		for i := range releases {
			var err error
			releases[i], err = d.Retain()
			if err != nil {
				t.Fatal(err)
			}
		}
		var wg sync.WaitGroup
		wg.Add(count + 1)
		go func() { defer wg.Done(); _ = d.Close() }()
		for _, release := range releases {
			go func() { defer wg.Done(); release(); release() }()
		}
		wg.Wait()
		assertLifetimeRetired(t, d, transport)
	}
}
