package singmux

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/infra/socks"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
)

type UDPConn struct {
	Conn
}

func (c *UDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	addr, err = socks5.ReadAddr(&c.Conn)
	if err != nil {
		return 0, nil, err
	}
	var length uint16
	err = binary.Read(&c.Conn, binary.BigEndian, &length)
	if err != nil {
		return 0, nil, err
	}
	n, err = io.ReadFull(&c.Conn, b[:min(len(b), int(length))])
	if err != nil {
		return n, addr, err
	}
	if n < int(length) {
		if _, err = io.CopyN(io.Discard, &c.Conn, int64(int(length)-n)); err != nil {
			return n, addr, err
		}
		return n, addr, io.ErrShortBuffer
	}
	return n, addr, nil
}

func (c *UDPConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	if len(b) > math.MaxUint16 {
		return 0, syscall.EMSGSIZE
	}
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	if err = socks5.WriteNetAddr(addr, buf); err != nil {
		return 0, err
	}
	binary.Write(buf, binary.BigEndian, uint16(len(b)))
	buf.Write(b)
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	n, err = c.write(buf.Bytes())
	if n > 0 && n < buf.Len() {
		c.writeErr = err
	}
	return max(0, n-(buf.Len()-len(b))), err
}

// smuxPacketConn writes datagrams to an smux stream without waiting: each is
// queued as its own frames in the session's scheduler, which drops queued
// datagrams that wait too long or overflow its limits; see
// netproxy.NonBlockingWriter and fq.Scheduler. Reads stay with UDPConn.
type smuxPacketConn struct {
	UDPConn
	leased *leasedStream
	stream *smuxStream

	request   []byte // sent with the first datagram, which is never dropped
	mu        sync.Mutex
	requested atomic.Bool
}

func newSmuxPacketConn(leased *leasedStream, stream *smuxStream, layer netproxy.FailureLayer, addr string) (*smuxPacketConn, error) {
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	if err := WriteStreamRequest(buf, &StreamRequest{Destination: addr, UDP: true, PacketAddr: true}); err != nil {
		_ = leased.Close()
		return nil, err
	}
	return &smuxPacketConn{
		UDPConn: UDPConn{Conn: Conn{Conn: leased, layer: layer, addr: addr, udp: true, packetAddr: true, onceWrite: true}},
		leased:  leased, stream: stream, request: bytes.Clone(buf.Bytes()),
	}, nil
}

// WriteTo reports a dropped datagram as written: to callers that do not
// account sent datagrams, as quic-go or DNS, ErrPacketDropped would be a
// failure.
func (c *smuxPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := c.TryWriteTo(b, addr)
	if err == netproxy.ErrPacketDropped {
		return len(b), nil
	}
	return n, err
}

func (c *smuxPacketConn) TryWriteTo(b []byte, addr net.Addr) (int, error) {
	if !c.requested.Load() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if !c.requested.Load() {
			return c.writeTo(b, addr, c.request)
		}
	}
	return c.writeTo(b, addr, nil)
}

// writeTo queues one datagram behind request, if any, which forces it.
func (c *smuxPacketConn) writeTo(b []byte, addr net.Addr, request []byte) (int, error) {
	if len(b) > math.MaxUint16 {
		return 0, syscall.EMSGSIZE
	}
	var header [socks.MaxAddrLen + 2]byte
	prefix, err := socks5.AppendNetAddr(header[:0], addr)
	if err != nil {
		return 0, err
	}
	prefix = binary.BigEndian.AppendUint16(prefix, uint16(len(b)))
	err = c.stream.writeDatagram(request, prefix, b)
	if request != nil && err == nil {
		c.requested.Store(true)
	}
	switch {
	case err == nil:
		return len(b), nil
	case err == netproxy.ErrPacketDropped:
		return 0, err
	default:
		return 0, c.leased.failure(err, netproxy.OpWrite)
	}
}

// SetPacketHandler pushes datagrams from the receive loop of the session; see
// netproxy.PacketPusher. Replies only follow the request, which goes with the
// first datagram, so no datagram can have been read or buffered unseen.
func (c *smuxPacketConn) SetPacketHandler(onPacket func(payload []byte, from netip.AddrPort), onClose func(error)) bool {
	if c.requested.Load() {
		panic("singmux: packet handler set after the first datagram")
	}
	r := &datagramReader{onPacket: onPacket, layer: c.layer}
	c.stream.setPush(r.feed, func(err error) {
		if r.packet != nil {
			pool.PutBuffer(r.packet)
			r.packet = nil
		}
		switch {
		case err != nil && err == r.failed:
		case r.state == readingRejection && err == io.EOF:
			err = rejection(c.layer, r.message)
		default:
			err = c.leased.failure(err, netproxy.OpRead)
		}
		onClose(err)
	})
	return true
}

const (
	readingStatus = iota
	readingHeader
	readingPayload
	readingRejection
)

// datagramReader parses the stream response and the datagrams after it as
// they arrive, in any split: [SOCKS address][length][payload].
type datagramReader struct {
	onPacket func([]byte, netip.AddrPort)
	layer    netproxy.FailureLayer
	state    int
	header   [socks.MaxAddrLen + 2]byte
	headLen  int
	from     netip.AddrPort
	length   int
	packet   []byte // pooled; a payload spanning frames
	have     int
	message  []byte // of a rejection
	failed   error  // ends delivery: an invalid address or a rejection
}

// datagramHeaderSize is the size of the address and length that b starts,
// 0 if b is too short to tell, or -1 for an invalid address.
func datagramHeaderSize(b []byte) int {
	switch {
	case len(b) == 0:
		return 0
	case b[0] == socks.ATypIP4:
		return 1 + 4 + 2 + 2
	case b[0] == socks.ATypIP6:
		return 1 + 16 + 2 + 2
	case b[0] != socks.ATypDomain:
		return -1
	case len(b) < 2:
		return 0
	case b[1] == 0:
		return -1
	}
	return 2 + int(b[1]) + 2 + 2
}

func (r *datagramReader) fail(err error) error {
	r.failed = err
	return err
}

func (r *datagramReader) feed(data []byte) error {
	for len(data) > 0 {
		switch r.state {
		case readingStatus:
			r.state = readingHeader
			if data[0] == statusError {
				r.state = readingRejection
			}
			data = data[1:]
		case readingRejection:
			n := min(len(data), maxRejectionMessageBytes+1-len(r.message))
			r.message = append(r.message, data[:n]...)
			data = data[n:]
			if len(r.message) > maxRejectionMessageBytes {
				return r.fail(rejection(r.layer, r.message))
			}
		case readingHeader:
			var header []byte
			if r.headLen == 0 {
				if size := datagramHeaderSize(data); size > 0 && size <= len(data) {
					header, data = data[:size], data[size:]
				}
			}
			if header == nil {
				// The header spans payloads: gather it.
				for len(data) > 0 {
					size := datagramHeaderSize(r.header[:r.headLen])
					if size < 0 || size > 0 && r.headLen == size {
						break
					}
					want := r.headLen + 1
					if size > 0 {
						want = size
					}
					n := copy(r.header[r.headLen:want], data)
					r.headLen += n
					data = data[n:]
				}
				size := datagramHeaderSize(r.header[:r.headLen])
				if size < 0 {
					return r.fail(fmt.Errorf("read SOCKS address: %w", socks.Errors[8]))
				}
				if size == 0 || r.headLen < size {
					return nil
				}
				header = r.header[:size]
			}
			size := len(header)
			r.headLen = 0
			port := binary.BigEndian.Uint16(header[size-4:])
			switch header[0] {
			case socks.ATypIP4:
				r.from = netip.AddrPortFrom(netip.AddrFrom4([4]byte(header[1:5])), port)
			case socks.ATypIP6:
				r.from = netip.AddrPortFrom(netip.AddrFrom16([16]byte(header[1:17])), port)
			default:
				// Replies come from IPs; a reader in control ends on this too.
				return r.fail(fmt.Errorf("receive UDP reply address: %s is not an IP address", net.JoinHostPort(string(header[2:size-4]), strconv.Itoa(int(port)))))
			}
			r.length, r.have = int(binary.BigEndian.Uint16(header[size-2:])), 0
			r.state = readingPayload
			if r.length == 0 {
				r.state = readingHeader
				r.onPacket(nil, r.from)
			}
		case readingPayload:
			if r.packet == nil && len(data) >= r.length {
				r.onPacket(data[:r.length], r.from)
				data = data[r.length:]
				r.state = readingHeader
				continue
			}
			if r.packet == nil {
				r.packet = pool.GetBuffer(r.length)
			}
			n := copy(r.packet[r.have:r.length], data)
			r.have += n
			data = data[n:]
			if r.have == r.length {
				r.onPacket(r.packet[:r.length], r.from)
				pool.PutBuffer(r.packet)
				r.packet = nil
				r.state = readingHeader
			}
		}
	}
	return nil
}

var _ netproxy.PacketPusher = (*smuxPacketConn)(nil)
