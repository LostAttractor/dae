// SPDX-License-Identifier: AGPL-3.0-only

package tuic

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/common"
	"github.com/daeuniverse/quic-go"
)

type establishmentPacketConn struct {
	*net.UDPConn
	lease  *netproxy.Lease
	closed atomic.Bool
}

func (c *establishmentPacketConn) DependencyLease() *netproxy.Lease { return c.lease }
func (c *establishmentPacketConn) Close() error                     { c.closed.Store(true); return c.UDPConn.Close() }

func TestEstablishQUICOwnsCleanupAndDependency(t *testing.T) {
	for _, scenario := range []string{"authentication", "canceled", "dependency", "ready"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			listener, err := quic.ListenAddr("127.0.0.1:0", recoveryTLS(t), &quic.Config{})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			packet := &establishmentPacketConn{UDPConn: udp, lease: netproxy.NewLease(netproxy.NewResourceRef())}
			defer packet.Close()
			cause := errors.New("establishment failed")
			want := cause
			ref := netproxy.NewResourceRef()
			var conn *quic.Conn
			result, err := common.EstablishQUIC(ctx, nil, func(context.Context, netproxy.Dialer) (*quic.Transport, net.Addr, error) {
				return &quic.Transport{Conn: packet}, listener.Addr(), nil
			}, ref, common.QUICHooks{
				TLSConfig:  &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"tuic-test"}},
				QUICConfig: &quic.Config{}, AuthenticationError: ProtocolError,
				Authenticate: func(_ context.Context, established *quic.Conn) error {
					conn = established
					switch scenario {
					case "authentication":
						return cause
					case "canceled":
						cancel()
						want = context.Canceled
					case "dependency":
						packet.lease.Invalidate(cause)
					}
					return nil
				},
			})
			if scenario == "ready" {
				if err != nil {
					t.Fatal(err)
				}
				defer result.Transport.Close()
				defer result.Conn.CloseWithError(0, "test complete")
				defer result.Lease.Invalidate(net.ErrClosed)
				failed := make(chan error, 1)
				result.WatchFailure(func(err error) { failed <- err })
				packet.lease.Abort(cause)
				select {
				case err := <-failed:
					if !errors.Is(err, cause) || result.Lease.Valid() {
						t.Fatalf("dependency failure = %v", err)
					}
				case <-ctx.Done():
					t.Fatal("dependency invalidation did not notify the owner")
				}
				return
			}
			if !errors.Is(err, want) || conn == nil || conn.Context().Err() == nil || !packet.closed.Load() {
				t.Fatalf("failed establishment leaked resources: error=%v connection=%v packetClosed=%v", err, conn, packet.closed.Load())
			}
			if scenario == "authentication" {
				failure := netproxy.ClassifyFailure(err)
				if failure.Resource != ref || failure.Phase != netproxy.OpHandshake {
					t.Fatalf("authentication failure lost attribution: %+v", failure)
				}
			}
		})
	}
}
