package tuic

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/quic-go"
)

const (
	AuthenticateType byte = iota
	ConnectType
	PacketType
	DissociateType
	HeartbeatType
)

// WriteAuthentication is the client authentication frame shared by TUIC v5
// and Juicity v0. Authentication decoding belongs to the peer.
func WriteAuthentication(w io.Writer, version byte, state quic.ConnectionState, id [16]byte, password string) error {
	token, err := state.TLS.ExportKeyingMaterial(string(id[:]), []byte(password), 32)
	if err != nil {
		return err
	}
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	buf.Write([]byte{version, AuthenticateType})
	buf.Write(id[:])
	buf.Write(token)
	_, err = buf.WriteTo(w)
	return err
}

const (
	AtypDomainName byte = 0
	AtypIPv4       byte = 1
	AtypIPv6       byte = 2
	AtypNone       byte = 255
)

type address struct {
	TYPE byte
	ADDR []byte
	PORT uint16
}

func addressFromMetadata(metadata *protocol.Metadata) *address {
	a := &address{PORT: metadata.Port}
	switch metadata.Type {
	case protocol.MetadataTypeIPv4:
		a.TYPE, a.ADDR = AtypIPv4, net.ParseIP(metadata.Hostname).To4()
	case protocol.MetadataTypeIPv6:
		a.TYPE, a.ADDR = AtypIPv6, net.ParseIP(metadata.Hostname).To16()
	default:
		a.TYPE = AtypDomainName
		a.ADDR = append([]byte{byte(len(metadata.Hostname))}, metadata.Hostname...)
	}
	return a
}

func readAddress(r io.Reader) (*address, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:1]); err != nil {
		return nil, err
	}
	a := &address{TYPE: head[0]}
	size := 0
	switch a.TYPE {
	case AtypNone:
		return a, nil
	case AtypIPv4:
		size = net.IPv4len
	case AtypIPv6:
		size = net.IPv6len
	case AtypDomainName:
		if _, err := io.ReadFull(r, head[1:]); err != nil {
			return nil, err
		}
		size = int(head[1])
		a.ADDR = append(a.ADDR, head[1])
	default:
		return nil, fmt.Errorf("invalid TUIC address type: %d", a.TYPE)
	}
	a.ADDR = append(a.ADDR, make([]byte, size)...)
	if _, err := io.ReadFull(r, a.ADDR[len(a.ADDR)-size:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	a.PORT = binary.BigEndian.Uint16(head[:])
	return a, nil
}

func (a *address) appendTo(buf *bytes.Buffer) error {
	if a == nil {
		return fmt.Errorf("missing TUIC address")
	}
	switch a.TYPE {
	case AtypNone:
		return buf.WriteByte(AtypNone)
	case AtypIPv4:
		if len(a.ADDR) != 4 {
			return fmt.Errorf("invalid TUIC IPv4 address")
		}
	case AtypIPv6:
		if len(a.ADDR) != 16 {
			return fmt.Errorf("invalid TUIC IPv6 address")
		}
	case AtypDomainName:
		if len(a.ADDR) < 2 || len(a.ADDR) > 256 || int(a.ADDR[0]) != len(a.ADDR)-1 {
			return fmt.Errorf("invalid TUIC domain length")
		}
	default:
		return fmt.Errorf("invalid TUIC address type: %d", a.TYPE)
	}
	buf.WriteByte(a.TYPE)
	buf.Write(a.ADDR)
	buf.Write(binary.BigEndian.AppendUint16(nil, a.PORT))
	return nil
}

func (a *address) netAddr() net.Addr {
	if a.TYPE == AtypDomainName {
		return netproxy.NewAddr("udp", a.String())
	}
	return &net.UDPAddr{IP: a.ADDR, Port: int(a.PORT)}
}

func (a *address) String() string {
	if a.TYPE == AtypDomainName {
		return net.JoinHostPort(string(a.ADDR[1:]), strconv.Itoa(int(a.PORT)))
	}
	ip, _ := netip.AddrFromSlice(a.ADDR)
	return netip.AddrPortFrom(ip, a.PORT).String()
}

func (a *address) BytesLen() int {
	if a.TYPE == AtypNone {
		return 1
	}
	return 3 + len(a.ADDR)
}

type packetFrame struct {
	ASSOC_ID   uint16
	PKT_ID     uint16
	FRAG_TOTAL uint8
	FRAG_ID    uint8
	ADDR       *address
	DATA       []byte
}

// readPacket consumes a server UDP frame. The caller has consumed its two-byte command.
func readPacket(r io.Reader) (*packetFrame, error) {
	var header [8]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	p := &packetFrame{ASSOC_ID: binary.BigEndian.Uint16(header[:]), PKT_ID: binary.BigEndian.Uint16(header[2:]), FRAG_TOTAL: header[4], FRAG_ID: header[5]}
	if p.FRAG_TOTAL == 0 || p.FRAG_ID >= p.FRAG_TOTAL {
		return nil, fmt.Errorf("invalid TUIC fragment index")
	}
	var err error
	p.ADDR, err = readAddress(r)
	if err != nil {
		return nil, err
	}
	if (p.FRAG_ID == 0) == (p.ADDR.TYPE == AtypNone) {
		return nil, fmt.Errorf("invalid TUIC fragment address")
	}
	p.DATA = make([]byte, binary.BigEndian.Uint16(header[6:]))
	_, err = io.ReadFull(r, p.DATA)
	return p, err
}

func (p *packetFrame) appendTo(buf *bytes.Buffer) error {
	buf.Write([]byte{Ver5, PacketType})
	buf.Write(binary.BigEndian.AppendUint16(nil, p.ASSOC_ID))
	buf.Write(binary.BigEndian.AppendUint16(nil, p.PKT_ID))
	buf.Write([]byte{p.FRAG_TOTAL, p.FRAG_ID})
	buf.Write(binary.BigEndian.AppendUint16(nil, uint16(len(p.DATA))))
	if err := p.ADDR.appendTo(buf); err != nil {
		return err
	}
	buf.Write(p.DATA)
	return nil
}

const (
	ProtocolError = quic.ApplicationErrorCode(0xfffffff0)
)
