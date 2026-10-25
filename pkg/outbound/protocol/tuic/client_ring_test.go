package tuic

import (
	"context"
	"crypto/tls"
	"fmt"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/common"
	"github.com/daeuniverse/quic-go"
)

// The peer's stream limit reaches the ring: a member keeps taking streams
// while its credit is above the reserve, or half of what the peer granted if
// that is less, and then the ring asks for another member, which takes the
// next stream. A peer granting no more than the reserve still gets streams.
func TestRingReservesPeerStreamCredit(t *testing.T) {
	const reserved = 10
	for _, limit := range []int64{2 * reserved, reserved - 1} {
		t.Run(fmt.Sprint("limit=", limit), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			listener, err := quic.ListenAddr("127.0.0.1:0", recoveryTLS(t), &quic.Config{EnableDatagrams: true, MaxIncomingStreams: limit})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			accepted := make(chan *quic.Conn, 2)
			go func() {
				for {
					c, err := listener.Accept(ctx)
					if err != nil {
						return
					}
					accepted <- c
				}
			}()
			d, err := NewDialer(loopbackPacketParent{}, protocol.Header{ProxyAddress: listener.Addr().String(), User: "00000000-0000-0000-0000-000000000000", Password: "test", Feature1: "bbr", TlsConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"tuic-test"}}})
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			if err := d.Connect(ctx); err != nil {
				t.Fatal(err)
			}
			for i := range limit - min(reserved, limit/2) {
				conn, err := d.DialContext(ctx, "tcp", "example.test:443")
				if err != nil {
					t.Fatalf("member above its reserve refused stream %d: %v", i+1, err)
				}
				defer conn.Close()
			}
			if state := d.Snapshot(); state.RecoveryRequired {
				t.Fatalf("member above its reserve asked for another: %+v", state)
			}
			if _, err := d.DialContext(ctx, "tcp", "example.test:443"); !common.IsCapacityError(err) {
				t.Fatalf("member at its reserve took a stream: %v", err)
			}
			if state := d.Snapshot(); !state.RecoveryRequired {
				t.Fatalf("ring at its reserve asked for no member: %+v", state)
			}
			if err := d.Connect(ctx); err != nil {
				t.Fatal(err)
			}
			next, err := d.DialContext(ctx, "tcp", "example.test:443")
			if err != nil {
				t.Fatalf("new member refused a stream: %v", err)
			}
			defer next.Close()
			for i := range 2 {
				select {
				case server := <-accepted:
					// The peer leaves first; closing the dialer then waits for no stream.
					defer server.CloseWithError(0, "")
				case <-ctx.Done():
					t.Fatalf("server accepted %d connections, want 2", i)
				}
			}
		})
	}
}
