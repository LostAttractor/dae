// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/internal/testutil"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	quic "github.com/daeuniverse/quic-go"
)

var quicAdmissionDrops = netproxy.NewDrop("quic-admission-test", netproxy.DropUpload, "carrier_queue_full")

type quicAdmissionPacketConn struct {
	net.PacketConn
	conn *quic.Conn
}

func (c *quicAdmissionPacketConn) TryWriteTo(b []byte, _ net.Addr) (int, error) {
	if err := c.conn.TrySendDatagram(b); err != nil {
		if errors.Is(err, quic.ErrDatagramQueueFull) {
			quicAdmissionDrops.Add(1)
			return 0, netproxy.ErrPacketDropped
		}
		return 0, err
	}
	return len(b), nil
}

func (*quicAdmissionPacketConn) WriteTo([]byte, net.Addr) (int, error) {
	return 0, errors.New("worker fell back to blocking QUIC write")
}

func TestUDPQUICQueueDoesNotBlockOtherSources(t *testing.T) {
	pair := testutil.NewQUICPair(t)
	endpoints := new(UdpEndpointPool)
	t.Cleanup(endpoints.closeAll)
	slow, fast := testUdpKey(20001), testUdpKey(20002)
	dst := netip.MustParseAddrPort("192.0.2.1:443")
	carrier := &quicAdmissionPacketConn{PacketConn: newTestPacketConn(false), conn: pair.Client}
	written := make(chan struct{}, 1)
	endpoints.add(slow, newUdpEndpoint(&UdpEndpointOptions{PacketConn: carrier, NatTimeout: time.Minute}))
	endpoints.add(fast, newUdpEndpoint(&UdpEndpointOptions{PacketConn: &udpTaskBenchmarkConn{PacketConn: newTestPacketConn(false), written: written}, NatTimeout: time.Minute}))
	tasks := newUdpTaskPool(udpPacketWork.execute)
	tasks.maxWorkers = 1
	t.Cleanup(tasks.close)
	t.Cleanup(pair.ReleaseWrites)
	plane := &ControlPlane{ctx: t.Context(), udpTaskPool: tasks, udpEndpoints: endpoints}
	payload := make([]byte, 1000)
	dropped := quicAdmissionDrops.Load()
	err := pair.WhileStalled(t, func() error {
		full := false
		for range 256 {
			err := pair.Client.TrySendDatagram(payload)
			if errors.Is(err, quic.ErrDatagramQueueFull) {
				full = true
				break
			}
			if err != nil {
				return err
			}
		}
		if !full {
			return errors.New("stalled carrier did not fill")
		}
		for range 64 {
			if !tasks.emit(payload, udpPacketWork{plane: plane, src: slow, dst: dst, deadline: time.Now().Add(time.Minute)}) {
				return errors.New("slow source rejected at ingress")
			}
		}
		if !tasks.emit(payload, udpPacketWork{plane: plane, src: fast, dst: dst, deadline: time.Now().Add(time.Minute)}) {
			return errors.New("fast source rejected at ingress")
		}
		<-written
		tasks.close()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if quicAdmissionDrops.Load() == dropped {
		t.Fatal("test did not exercise full-carrier drops")
	}
}
