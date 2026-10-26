// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

func TestUDPSlowSlotNestingAndRelease(t *testing.T) {
	var active atomic.Int32
	active.Store(maxConcurrentUDPSlowWork - 1)
	slot, other := &udpWriteSlot{slow: &active}, &udpWriteSlot{slow: &active}
	if !slot.beginSlow() || active.Load() != maxConcurrentUDPSlowWork {
		t.Fatal("setup did not reserve one permit")
	}
	conn := newTestPacketConn(false)
	defer conn.Close()
	if n, err := writePacketUntil(t.Context(), time.Now().Add(time.Minute), slot, conn, []byte("first"), nil); err != nil || n != 5 {
		t.Fatalf("nested setup write: %d %v", n, err)
	}
	if active.Load() != maxConcurrentUDPSlowWork || slot.slowDepth != 1 {
		t.Fatal("nested write consumed or released the setup permit")
	}
	if other.beginSlow() {
		t.Fatal("another worker bypassed the shared limit")
	}
	slot.endSlow()
	if !other.beginSlow() {
		t.Fatal("completed setup did not return admission")
	}
	other.endSlow()
	if active.Load() != maxConcurrentUDPSlowWork-1 || slot.slowDepth != 0 || other.slowDepth != 0 {
		t.Fatal("permit leaked or was released twice")
	}
}

func TestUDPSlowWriteRejectionDoesNotTouchConnection(t *testing.T) {
	var active atomic.Int32
	active.Store(maxConcurrentUDPSlowWork)
	slot := &udpWriteSlot{slow: &active}
	conn := &deadlineRecordingPacketConn{testPacketConn: newTestPacketConn(false)}
	defer conn.Close()
	before := dropSlowWriteCapacity.Load()
	n, err := writePacketUntil(t.Context(), time.Now().Add(time.Minute), slot, conn, []byte("packet"), nil)
	if n != 0 || err != netproxy.ErrPacketDropped || dropSlowWriteCapacity.Load()-before != 1 {
		t.Fatalf("rejection: %d %v drops=%d", n, err, dropSlowWriteCapacity.Load()-before)
	}
	if len(conn.deadlines) != 0 || slot.conn != nil || slot.slowDepth != 0 || active.Load() != maxConcurrentUDPSlowWork {
		t.Fatal("rejected write changed the socket or admission state")
	}
	select {
	case <-conn.writeStarted:
		t.Fatal("rejected write reached transport")
	default:
	}
	select {
	case <-conn.closed:
		t.Fatal("capacity pressure closed the transport")
	default:
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := writePacketUntil(ctx, time.Time{}, slot, conn, nil, nil); !errors.Is(err, context.Canceled) || dropSlowWriteCapacity.Load()-before != 1 {
		t.Fatal("cancellation was counted as capacity loss")
	}
	fast := &readyAdmissionPacketConn{testPacketConn: newTestPacketConn(false), written: make(chan struct{}, 1)}
	defer fast.Close()
	if n, err := writePacketUntil(t.Context(), time.Time{}, slot, fast, []byte("ready"), nil); err != nil || n != 5 {
		t.Fatalf("ready transport waited for slow admission: %d %v", n, err)
	}
}

func TestUDPWorkerCancellationReturnsSlowAdmission(t *testing.T) {
	endpoints := new(UdpEndpointPool)
	defer endpoints.closeAll()
	conn := newTestPacketConn(true)
	src, dst := testUdpKey(33000), testUdpKey(443)
	endpoints.add(src, newUdpEndpoint(&UdpEndpointOptions{PacketConn: conn, NatTimeout: time.Hour}))
	tasks := newUdpTaskPool(udpPacketWork.execute)
	defer tasks.close()
	defer tasks.interrupt()
	plane := &ControlPlane{ctx: t.Context(), udpTaskPool: tasks, udpEndpoints: endpoints}
	if !tasks.emit([]byte("packet"), udpPacketWork{plane: plane, src: src, dst: dst, deadline: time.Now().Add(time.Minute)}) {
		t.Fatal("ingress rejected packet")
	}
	select {
	case <-conn.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("worker did not start write")
	}
	if got := plane.udpSlowWork.Load(); got != 1 {
		t.Fatalf("active slow operations=%d, want 1", got)
	}
	tasks.interrupt()
	tasks.close()
	if got := plane.udpSlowWork.Load(); got != 0 {
		t.Fatalf("canceled worker retained %d permits", got)
	}
}
