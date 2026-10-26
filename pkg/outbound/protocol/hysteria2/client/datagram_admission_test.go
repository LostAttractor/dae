// SPDX-License-Identifier: AGPL-3.0-only

package client

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
	"github.com/daeuniverse/dae/pkg/outbound/protocol/hysteria2/internal/protocol"
)

func TestDatagramAdmissionDoesNotWait(t *testing.T) {
	for _, size := range []int{1000, 60000} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			pair := testutil.NewQUICPair(t)
			parent := netproxy.NewLease(netproxy.NewResourceRef())
			var failures atomic.Int32
			manager := newUDPSessionManager(t.Context(), pair.Client)
			packet, err := manager.NewUDP(parent.NewStream(), func(error) { failures.Add(1) })
			if err != nil {
				t.Fatal(err)
			}
			u := packet.(*udpConn)
			t.Cleanup(func() { _ = u.Close() })
			addr := netproxy.NewAddr("udp", "example.test:53")
			if !netproxy.CanTryWriteTo(u) {
				t.Fatal("datagram relay did not expose nonblocking admission")
			}
			if n, err := u.TryWriteTo([]byte("first"), addr); err != nil || n != 5 {
				t.Fatalf("first write: %d %v", n, err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			wire, err := pair.Server.ReceiveDatagram(ctx)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := protocol.ParseUDPMessage(wire)
			if err != nil || string(decoded.Data) != "first" {
				t.Fatalf("wire payload: %+v, %v", decoded, err)
			}
			if size > 1000 {
				probe := bytes.Repeat([]byte("fragment"), 375)
				if n, err := u.TryWriteTo(probe, addr); err != nil || n != len(probe) {
					t.Fatalf("fragment write: %d %v", n, err)
				}
				for {
					wire, err := pair.Server.ReceiveDatagram(ctx)
					if err != nil {
						t.Fatal(err)
					}
					fragment, err := protocol.ParseUDPMessage(wire)
					if err != nil {
						t.Fatal(err)
					}
					if result := u.feedDefrag(fragment); result != nil {
						if !bytes.Equal(result.Data, probe) {
							t.Fatal("fragmented payload changed")
						}
						break
					}
				}
			}
			payload := make([]byte, size)
			before := netproxy.DropCarrierQueueFull.Load()
			err = pair.WhileStalled(t, func() error {
				for range 256 {
					n, err := u.TryWriteTo(payload, addr)
					if err != nil {
						if n != 0 {
							return fmt.Errorf("rejected datagram reported %d bytes", n)
						}
						return err
					}
				}
				return errors.New("stalled carrier did not fill")
			})
			if err != netproxy.ErrPacketDropped || netproxy.DropCarrierQueueFull.Load()-before != 1 || !u.lease.Valid() || !parent.Valid() || failures.Load() != 0 {
				t.Fatalf("admission: %v drops=%d failures=%d", err, netproxy.DropCarrierQueueFull.Load()-before, failures.Load())
			}
			before = netproxy.DropCarrierQueueFull.Load()
			err = pair.WhileStalled(t, func() error {
				for range 256 {
					n, err := u.WriteTo(payload, addr)
					if err != nil || n != len(payload) {
						return fmt.Errorf("WriteTo: n=%d err=%v", n, err)
					}
					if netproxy.DropCarrierQueueFull.Load() != before {
						return nil
					}
				}
				return errors.New("WriteTo did not report a counted drop")
			})
			if err != nil || netproxy.DropCarrierQueueFull.Load()-before != 1 {
				t.Fatalf("reported drop: %v, count=%d", err, netproxy.DropCarrierQueueFull.Load()-before)
			}
			_ = u.SetWriteDeadline(time.Now().Add(-time.Second))
			if _, err := u.TryWriteTo(payload, addr); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("expired write: %v", err)
			}
			_ = u.SetWriteDeadline(time.Time{})
			_ = u.Close()
			if _, err := u.TryWriteTo(payload, addr); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("closed write: %v", err)
			}
		})
	}
}
