package client

import (
	"bytes"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/protocol/hysteria2/internal/protocol"
)

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

func TestUDPConnLimitsIncompletePackets(t *testing.T) {
	u := new(udpConn)
	for i := 0; i < udpMessageChanSize+100; i++ {
		u.feedDefrag(&protocol.UDPMessage{PacketID: uint16(i), FragCount: 2, Addr: "127.0.0.1:53", Data: []byte("pending")})
	}
	if len(u.defraggers) != udpMessageChanSize {
		t.Fatalf("pending packets=%d", len(u.defraggers))
	}
}
