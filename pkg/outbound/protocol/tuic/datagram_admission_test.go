// SPDX-License-Identifier: AGPL-3.0-only

package tuic

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/internal/testutil"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/common"
)

func TestNativeDatagramAdmissionDoesNotWait(t *testing.T) {
	// 3000 bytes take several fragments, which a full queue rejects together.
	for _, size := range []int{1000, 3000} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			pair := testutil.NewQUICPair(t)
			parent := netproxy.NewLease(netproxy.NewResourceRef())
			var failures atomic.Int32
			q := &quicStreamPacketConn{quicConn: pair.Client, lease: parent.NewStream(), incomingPackets: newPacketQueue(), udpRelayMode: common.NATIVE, readDeadline: protocol.MakeDeadline(), fail: func(error) { failures.Add(1) }}
			t.Cleanup(func() { q.shutdown(net.ErrClosed) })
			addr := netproxy.NewAddr("udp", "example.test:53")
			if !netproxy.CanTryWriteTo(q) {
				t.Fatal("native relay did not expose nonblocking admission")
			}
			if n, err := q.TryWriteTo([]byte("first"), addr); err != nil || n != 5 {
				t.Fatalf("first write: %d %v", n, err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			wire, err := pair.Server.ReceiveDatagram(ctx)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := readPacket(bytes.NewReader(wire[2:]))
			if err != nil || string(decoded.DATA) != "first" {
				t.Fatalf("wire payload: %+v, %v", decoded, err)
			}
			if size > 1000 {
				q.maxUdpRelayPacketSize = 400
				probe := bytes.Repeat([]byte("fragment"), 375)
				if n, err := q.TryWriteTo(probe, addr); err != nil || n != len(probe) {
					t.Fatalf("fragment write: %d %v", n, err)
				}
				reassembly, result := new(deFragger), make([]byte, len(probe))
				for {
					wire, err := pair.Server.ReceiveDatagram(ctx)
					if err != nil {
						t.Fatal(err)
					}
					fragment, err := readPacket(bytes.NewReader(wire[2:]))
					if err != nil {
						t.Fatal(err)
					}
					if n, _, ready := reassembly.Feed(fragment, result); ready {
						if !bytes.Equal(result[:n], probe) {
							t.Fatal("fragmented payload changed")
						}
						break
					}
				}
			}
			payload := make([]byte, size)
			before := datagramDrops.CarrierQueueFull.Load()
			err = pair.WhileStalled(t, func() error {
				for range 256 {
					n, err := q.TryWriteTo(payload, addr)
					if err != nil {
						if n != 0 {
							return fmt.Errorf("rejected datagram reported %d bytes", n)
						}
						return err
					}
				}
				return errors.New("stalled carrier did not fill")
			})
			if err != netproxy.ErrPacketDropped || datagramDrops.CarrierQueueFull.Load()-before != 1 || !q.lease.Valid() || !parent.Valid() || failures.Load() != 0 {
				t.Fatalf("admission: %v drops=%d failures=%d", err, datagramDrops.CarrierQueueFull.Load()-before, failures.Load())
			}
			before = datagramDrops.CarrierQueueFull.Load()
			err = pair.WhileStalled(t, func() error {
				for range 256 {
					n, err := q.WriteTo(payload, addr)
					if err != nil || n != len(payload) {
						return fmt.Errorf("WriteTo: n=%d err=%v", n, err)
					}
					if datagramDrops.CarrierQueueFull.Load() != before {
						return nil
					}
				}
				return errors.New("WriteTo did not report a counted drop")
			})
			if err != nil || datagramDrops.CarrierQueueFull.Load()-before != 1 {
				t.Fatalf("reported drop: %v, count=%d", err, datagramDrops.CarrierQueueFull.Load()-before)
			}
			_ = q.SetWriteDeadline(time.Now().Add(-time.Second))
			if _, err := q.TryWriteTo(payload, addr); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("expired write: %v", err)
			}
			_ = q.SetWriteDeadline(time.Time{})
			q.shutdown(net.ErrClosed)
			if _, err := q.TryWriteTo(payload, addr); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("closed write: %v", err)
			}
		})
	}
}

// A datagram needing more fragments than the QUIC send queue holds is dropped
// whole: no fragment reaches the server.
func TestOversizedNativeDatagramIsDroppedWhole(t *testing.T) {
	pair := testutil.NewQUICPair(t)
	parent := netproxy.NewLease(netproxy.NewResourceRef())
	q := &quicStreamPacketConn{quicConn: pair.Client, lease: parent.NewStream(), incomingPackets: newPacketQueue(), udpRelayMode: common.NATIVE, readDeadline: protocol.MakeDeadline(), fail: func(err error) { t.Errorf("carrier failed: %v", err) }}
	t.Cleanup(func() { q.shutdown(net.ErrClosed) })
	addr := netproxy.NewAddr("udp", "example.test:53")
	before := datagramDrops.TooLarge.Load()
	if n, err := q.TryWriteTo(make([]byte, 60000), addr); err != netproxy.ErrPacketDropped || n != 0 {
		t.Fatalf("oversized write: %d %v", n, err)
	}
	if n := datagramDrops.TooLarge.Load() - before; n != 1 {
		t.Fatalf("counted %d too_large drops, want 1", n)
	}
	if _, err := q.TryWriteTo([]byte("next"), addr); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	wire, err := pair.Server.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := readPacket(bytes.NewReader(wire[2:])); err != nil || string(decoded.DATA) != "next" {
		t.Fatalf("first datagram sent: %+v, %v", decoded, err)
	}
}

func TestStreamDatagramDoesNotClaimNonblockingAdmission(t *testing.T) {
	q := &quicStreamPacketConn{udpRelayMode: common.QUIC}
	if netproxy.CanTryWriteTo(q) {
		t.Fatal("stream relay claimed nonblocking admission")
	}
	if n, err := q.TryWriteTo([]byte("packet"), nil); n != 0 || err != errors.ErrUnsupported {
		t.Fatalf("unsupported relay: %d %v", n, err)
	}
}
