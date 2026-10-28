package tuic

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	quicgo "github.com/daeuniverse/quic-go"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/common"
)

func TestDialerHonorsUDPRelayMode(t *testing.T) {
	for _, quic := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		listener, err := quicgo.ListenAddr("127.0.0.1:0", recoveryTLS(t), &quicgo.Config{EnableDatagrams: true})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		header := protocol.Header{ProxyAddress: listener.Addr().String(), User: "00000000-0000-0000-0000-000000000001", Feature1: "bbr", TlsConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"tuic-test"}}}
		want := common.NATIVE
		if quic {
			header.Flags |= protocol.Flags_Tuic_UdpRelayModeQuic
			want = common.QUIC
		}
		dialer, err := NewDialer(loopbackPacketParent{}, header)
		if err != nil {
			t.Fatal(err)
		}
		if err := dialer.Connect(ctx); err != nil {
			t.Fatal(err)
		}
		if err := dialer.clientRing.Allocate(ctx, false, func(_ context.Context, client *clientImpl) error {
			if client.UdpRelayMode != want {
				t.Fatalf("relay mode=%v want=%v", client.UdpRelayMode, want)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		// The peer leaves first; closing the dialer then waits for no stream.
		server, err := listener.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_ = server.CloseWithError(0, "")
		if err := dialer.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestClientFrameWireFormat(t *testing.T) {
	for _, tc := range []struct{ address, wire string }{
		{"1.2.3.4:443", "010102030401bb"},
		{"[2001:db8::1]:53", "0220010db80000000000000000000000010035"},
		{"example.com:80", "000b6578616d706c652e636f6d0050"},
	} {
		t.Run(tc.address, func(t *testing.T) {
			m, err := protocol.ParseMetadata(tc.address)
			if err != nil {
				t.Fatal(err)
			}
			buf := new(bytes.Buffer)
			if err = addressFromMetadata(&m).appendTo(buf); err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(buf.Bytes()) != tc.wire {
				t.Fatalf("address wire=%x", buf.Bytes())
			}
			addr, err := readAddress(buf)
			if err != nil || addr.String() != tc.address {
				t.Fatalf("read address=%v err=%v", addr, err)
			}
		})
	}
	m, _ := protocol.ParseMetadata("1.2.3.4:53")
	packet := &packetFrame{ASSOC_ID: 0x1234, PKT_ID: 0x5678, FRAG_TOTAL: 1, ADDR: addressFromMetadata(&m), DATA: []byte("abc")}
	buf := new(bytes.Buffer)
	if err := packet.appendTo(buf); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(buf.Bytes()); got != "0502123456780100000301010203040035616263" {
		t.Fatal(got)
	}
	decoded, err := readPacket(bytes.NewReader(buf.Bytes()[2:]))
	if err != nil || string(decoded.DATA) != "abc" {
		t.Fatalf("decode=%+v err=%v", decoded, err)
	}
	if _, err = readAddress(bytes.NewReader([]byte{AtypNone})); err != nil {
		t.Fatal(err)
	}
	if _, err = readAddress(bytes.NewReader([]byte{3, 0, 0})); err == nil {
		t.Fatal("accepted unknown address type")
	}
	if _, err = readPacket(bytes.NewReader([]byte{0, 0, 0, 0, 2, 2, 0, 0, AtypNone})); err == nil {
		t.Fatal("accepted invalid fragment")
	}
}

func TestPacketQueueAndReassemblyAreBounded(t *testing.T) {
	full, closed := netproxy.DropReceiveFull.Load(), netproxy.DropClosedStream.Load()
	queue := newPacketQueue()
	for i := 0; i < packetQueueSize*2; i++ {
		queue.PushBack(&packetFrame{})
	}
	if len(queue.packets) != packetQueueSize || netproxy.DropReceiveFull.Load()-full != packetQueueSize {
		t.Fatalf("queue length=%d, %d drops counted", len(queue.packets), netproxy.DropReceiveFull.Load()-full)
	}
	queue.Close()
	select {
	case <-queue.done:
	default:
		t.Fatal("close did not wake reader")
	}
	queue.PushBack(&packetFrame{})
	if netproxy.DropClosedStream.Load()-closed != 1 {
		t.Fatal("a packet for a closed association was not counted")
	}
	m, _ := protocol.ParseMetadata("127.0.0.1:53")
	d := new(deFragger)
	for _, index := range []uint8{1, 1, 0} {
		n, addr, ready := d.Feed(&packetFrame{FRAG_TOTAL: 2, FRAG_ID: index, ADDR: addressFromMetadata(&m), DATA: []byte{byte('a' + index)}}, make([]byte, 2))
		if ready && (n != 2 || addr.String() != "127.0.0.1:53") {
			t.Fatalf("assembly=%d %v", n, addr)
		}
	}
	// A packet ID reused with another fragment count must reset, never index
	// the old slice or treat duplicates as completion.
	if _, _, ready := d.Feed(&packetFrame{FRAG_TOTAL: 3, FRAG_ID: 2, ADDR: &address{TYPE: AtypNone}, DATA: []byte("c")}, make([]byte, 3)); ready {
		t.Fatal("mixed fragment counts assembled")
	}
}

// A fragment that would start a datagram beyond the full reassembly table
// is dropped and counted.
func TestReassemblyTableDropIsCounted(t *testing.T) {
	q := &quicStreamPacketConn{lease: netproxy.NewLease(netproxy.NewResourceRef()), incomingPackets: newPacketQueue(), readDeadline: protocol.MakeDeadline(),
		fragments: make(map[uint16]*deFragger)}
	defer q.incomingPackets.Close()
	for id := range uint16(packetQueueSize) {
		q.fragments[id] = &deFragger{updated: time.Now()}
	}
	m, _ := protocol.ParseMetadata("127.0.0.1:53")
	dropped := netproxy.DropReceiveFull.Load()
	q.incomingPackets.PushBack(&packetFrame{PKT_ID: packetQueueSize, FRAG_TOTAL: 2, ADDR: addressFromMetadata(&m), DATA: []byte("a")})
	q.incomingPackets.PushBack(&packetFrame{FRAG_TOTAL: 1, ADDR: addressFromMetadata(&m), DATA: []byte("ok")})
	data := make([]byte, 8)
	if n, _, err := q.ReadFrom(data); err != nil || string(data[:n]) != "ok" {
		t.Fatalf("read %q %v", data[:n], err)
	}
	if n := netproxy.DropReceiveFull.Load() - dropped; n != 1 {
		t.Fatalf("counted %d drops, want 1", n)
	}
}

func TestUDPReadReportsTruncation(t *testing.T) {
	for _, fragments := range []int{1, 2} {
		for _, size := range []int{0, 1, 4, 8} {
			t.Run(fmt.Sprintf("fragments=%d/buffer=%d", fragments, size), func(t *testing.T) {
				q := &quicStreamPacketConn{lease: netproxy.NewLease(netproxy.NewResourceRef()), incomingPackets: newPacketQueue(), readDeadline: protocol.MakeDeadline()}
				defer q.incomingPackets.Close()
				m, _ := protocol.ParseMetadata("127.0.0.1:53")
				payload := []byte("data")
				for i := fragments - 1; i >= 0; i-- {
					q.incomingPackets.PushBack(&packetFrame{PKT_ID: 1, FRAG_TOTAL: uint8(fragments), FRAG_ID: uint8(i), ADDR: addressFromMetadata(&m), DATA: payload[i*len(payload)/fragments : (i+1)*len(payload)/fragments]})
				}
				q.incomingPackets.PushBack(&packetFrame{FRAG_TOTAL: 1, ADDR: addressFromMetadata(&m), DATA: []byte("next")})
				buf := make([]byte, size)
				n, addr, err := q.ReadFrom(buf)
				var wantErr error
				if size < len(payload) {
					wantErr = io.ErrShortBuffer
				}
				if n != min(size, len(payload)) || !bytes.Equal(buf[:n], payload[:n]) || addr == nil || addr.String() != "127.0.0.1:53" || !errors.Is(err, wantErr) {
					t.Fatalf("ReadFrom = %q, %v, %v", buf[:n], addr, err)
				}
				if !q.lease.Valid() || len(q.fragments) != 0 {
					t.Fatal("truncation invalidated the association or retained fragments")
				}
				buf = make([]byte, 8)
				if n, _, err := q.ReadFrom(buf); err != nil || string(buf[:n]) != "next" {
					t.Fatalf("next datagram = %q, %v", buf[:n], err)
				}
			})
		}
	}
}

func TestUDPDeadlineClearsWithoutClosingAssociation(t *testing.T) {
	parent := netproxy.NewLease(netproxy.NewResourceRef())
	q := &quicStreamPacketConn{lease: parent.NewStream(), incomingPackets: newPacketQueue(), readDeadline: protocol.MakeDeadline()}
	defer q.incomingPackets.Close()
	if err := q.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	_, _, err := q.ReadFrom(make([]byte, 8))
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() || !q.lease.Valid() || !parent.Valid() {
		t.Fatalf("deadline=%v", err)
	}
	q.SetReadDeadline(time.Time{})
	m, _ := protocol.ParseMetadata("127.0.0.1:53")
	q.incomingPackets.PushBack(&packetFrame{FRAG_TOTAL: 1, ADDR: addressFromMetadata(&m), DATA: []byte("ok")})
	data := make([]byte, 8)
	if n, _, err := q.ReadFrom(data); err != nil || string(data[:n]) != "ok" {
		t.Fatalf("after reset=%q %v", data, err)
	}
	done := make(chan error, 1)
	go func() { _, _, err := q.ReadFrom(data); done <- err }()
	q.incomingPackets.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("closed queue blocked reader")
	}
}
