package client

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	P "github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/hysteria2/internal/protocol"
)

func TestUDPReadReportsTruncation(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:53", "dns.example:53"} {
		for _, fragments := range []int{1, 2} {
			for _, size := range []int{0, 1, 4, 8} {
				t.Run(fmt.Sprintf("%s/fragments=%d/buffer=%d", addr, fragments, size), func(t *testing.T) {
					u := &udpConn{ctx: t.Context(), lease: netproxy.NewLease(netproxy.NewResourceRef()), readDeadline: P.MakeDeadline(), ReceiveCh: make(chan *protocol.UDPMessage, 3)}
					payload := []byte("data")
					for i := fragments - 1; i >= 0; i-- {
						u.ReceiveCh <- &protocol.UDPMessage{PacketID: 1, FragCount: uint8(fragments), FragID: uint8(i), Addr: addr, Data: payload[i*len(payload)/fragments : (i+1)*len(payload)/fragments]}
					}
					u.ReceiveCh <- &protocol.UDPMessage{FragCount: 1, Addr: addr, Data: []byte("next")}
					buf := make([]byte, size)
					n, from, err := u.ReadFrom(buf)
					var wantErr error
					if size < len(payload) {
						wantErr = io.ErrShortBuffer
					}
					if n != min(size, len(payload)) || !bytes.Equal(buf[:n], payload[:n]) || from == nil || from.String() != addr || !errors.Is(err, wantErr) {
						t.Fatalf("ReadFrom = %q, %v, %v", buf[:n], from, err)
					}
					if !u.lease.Valid() || len(u.defraggers) != 0 {
						t.Fatal("truncation invalidated the association or retained fragments")
					}
					buf = make([]byte, 8)
					if n, _, err := u.ReadFrom(buf); err != nil || string(buf[:n]) != "next" {
						t.Fatalf("next datagram = %q, %v", buf[:n], err)
					}
				})
			}
		}
	}
}

func TestUDPConnReassemblesInterleavedPackets(t *testing.T) {
	u := new(udpConn)
	message := func(packetID uint16, fragmentID uint8, data string) *protocol.UDPMessage {
		return &protocol.UDPMessage{
			SessionID: 1,
			PacketID:  packetID,
			FragID:    fragmentID,
			FragCount: 2,
			Addr:      "192.0.2.1:443",
			Data:      []byte(data),
		}
	}

	if got := u.feedDefrag(message(1, 0, "a")); got != nil {
		t.Fatalf("first fragment returned message: %+v", got)
	}
	if got := u.feedDefrag(message(2, 0, "b")); got != nil {
		t.Fatalf("interleaved first fragment returned message: %+v", got)
	}
	gotA := u.feedDefrag(message(1, 1, "A"))
	if gotA == nil || !bytes.Equal(gotA.Data, []byte("aA")) {
		t.Fatalf("packet 1 = %+v, want data aA", gotA)
	}
	gotB := u.feedDefrag(message(2, 1, "B"))
	if gotB == nil || !bytes.Equal(gotB.Data, []byte("bB")) {
		t.Fatalf("packet 2 = %+v, want data bB", gotB)
	}
	if len(u.defraggers) != 0 {
		t.Fatalf("completed defraggers retained: %d", len(u.defraggers))
	}
}

func TestUDPConnExpiresIncompletePacket(t *testing.T) {
	u := new(udpConn)
	incomplete := &protocol.UDPMessage{
		SessionID: 1,
		PacketID:  1,
		FragID:    0,
		FragCount: 2,
		Addr:      "192.0.2.1:443",
		Data:      []byte("incomplete"),
	}
	if got := u.feedDefrag(incomplete); got != nil {
		t.Fatalf("first fragment returned message: %+v", got)
	}

	u.receiveMu.Lock()
	u.defraggers[1].expiresAt = time.Now().Add(-time.Second)
	u.lastSweep = time.Time{}
	u.receiveMu.Unlock()

	complete := &protocol.UDPMessage{FragCount: 1, Data: []byte("complete")}
	if got := u.feedDefrag(complete); got != complete {
		t.Fatalf("unfragmented message = %+v, want original", got)
	}
	if len(u.defraggers) != 0 {
		t.Fatalf("expired defraggers retained: %d", len(u.defraggers))
	}
}

// A fragment beyond the full reassembly table is dropped and counted.
func TestUDPConnLimitsIncompletePackets(t *testing.T) {
	u := new(udpConn)
	dropped := netproxy.DropReceiveFull.Load()
	for i := 0; i < udpMessageChanSize+100; i++ {
		u.feedDefrag(&protocol.UDPMessage{PacketID: uint16(i), FragCount: 2, Addr: "127.0.0.1:53", Data: []byte("pending")})
	}
	if len(u.defraggers) != udpMessageChanSize || netproxy.DropReceiveFull.Load()-dropped != 100 {
		t.Fatalf("pending packets=%d, %d drops counted", len(u.defraggers), netproxy.DropReceiveFull.Load()-dropped)
	}
}
