package tuic

import (
	"bytes"
	"github.com/daeuniverse/quic-go"
	"net"
	"time"
)

func fragWriteNative(conn *quic.Conn, packet *packetFrame, buf *bytes.Buffer, size int) error {
	if size <= 0 || (len(packet.DATA)+size-1)/size > 255 {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: int64(max(0, size) * 255)}
	}
	count := (len(packet.DATA) + size - 1) / size
	for id, offset := 0, 0; offset < len(packet.DATA); id++ {
		fragment := *packet
		fragment.FRAG_ID, fragment.FRAG_TOTAL = uint8(id), uint8(count)
		end := min(len(packet.DATA), offset+size)
		fragment.DATA = packet.DATA[offset:end]
		if id > 0 {
			fragment.ADDR = &address{TYPE: AtypNone}
		}
		buf.Reset()
		if err := fragment.appendTo(buf); err != nil {
			return err
		}
		if err := conn.SendDatagram(buf.Bytes()); err != nil {
			return err
		}
		offset = end
	}
	return nil
}

type deFragger struct {
	frags   []*packetFrame
	count   int
	size    int
	updated time.Time
}

func (d *deFragger) Feed(packet *packetFrame, p []byte) (int, net.Addr, bool) {
	if packet.FRAG_TOTAL < 2 || packet.FRAG_ID >= packet.FRAG_TOTAL {
		return 0, nil, false
	}
	if len(d.frags) != int(packet.FRAG_TOTAL) {
		d.frags = make([]*packetFrame, packet.FRAG_TOTAL)
		d.count, d.size = 0, 0
	}
	if d.frags[packet.FRAG_ID] != nil {
		return 0, nil, false
	}
	d.size += len(packet.DATA)
	if d.size > 65535 {
		d.frags = nil
		d.count, d.size = 0, 0
		return 0, nil, false
	}
	d.frags[packet.FRAG_ID] = packet
	d.count++
	if d.count != len(d.frags) {
		return 0, nil, false
	}
	n := 0
	for _, fragment := range d.frags {
		n += copy(p[n:], fragment.DATA)
	}
	return n, d.frags[0].ADDR.netAddr(), true
}
