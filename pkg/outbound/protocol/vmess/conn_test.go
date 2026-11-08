package vmess

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
)

type wireConn struct {
	net.Conn
	input  *bytes.Reader
	output bytes.Buffer
	short  bool
	writes int
	closed bool
	lease  *netproxy.Lease
}

func (c *wireConn) Read(p []byte) (int, error) { return c.input.Read(p) }
func (c *wireConn) Write(p []byte) (int, error) {
	c.writes++
	if c.short {
		return len(p) - 1, nil
	}
	return c.output.Write(p)
}
func (c *wireConn) Close() error                     { c.closed = true; return nil }
func (c *wireConn) SetDeadline(time.Time) error      { return nil }
func (c *wireConn) DependencyLease() *netproxy.Lease { return c.lease }

var wireKey = bytes.Repeat([]byte{7}, 16)

// parseRequest decodes the AEAD request header at the start of wire as the
// server does and returns its instruction and the bytes that follow it.
func parseRequest(t *testing.T, wire []byte) (request, rest []byte) {
	t.Helper()
	if len(wire) < 58 {
		t.Fatalf("short request: %x", wire)
	}
	auth, nonce := wire[:16], wire[34:42]
	aead, _ := NewAesGcm(KDF(wireKey, []byte(KDFSaltConstVMessHeaderPayloadLengthAEADKey), auth, nonce)[:16])
	size, err := aead.Open(nil, KDF(wireKey, []byte(KDFSaltConstVMessHeaderPayloadLengthAEADIV), auth, nonce)[:12], wire[16:34], auth)
	if err != nil {
		t.Fatal(err)
	}
	end := 58 + int(binary.BigEndian.Uint16(size))
	if len(wire) < end {
		t.Fatalf("truncated request: %x", wire)
	}
	aead, _ = NewAesGcm(KDF(wireKey, []byte(KDFSaltConstVMessHeaderPayloadAEADKey), auth, nonce)[:16])
	request, err = aead.Open(nil, KDF(wireKey, []byte(KDFSaltConstVMessHeaderPayloadAEADIV), auth, nonce)[:12], wire[42:end], auth)
	if err != nil {
		t.Fatal(err)
	}
	sum := fnv.New32a()
	sum.Write(request[:len(request)-4])
	if binary.BigEndian.Uint32(request[len(request)-4:]) != sum.Sum32() {
		t.Fatal("request checksum")
	}
	return request, wire[end:]
}

// openChunks authenticates request body chunks as the server does.
func openChunks(t *testing.T, request, wire []byte, count uint32) []string {
	t.Helper()
	body, _ := NewAesGcm(request[17:33])
	mask := NewShakeSizeParser(request[1:17])
	var chunks []string
	for len(wire) > 0 {
		padding := int(mask.NextPaddingLen())
		size, _ := mask.Decode(wire[:2])
		plain, err := body.Open(nil, chunkNonce([16]byte(request[1:17]), count, body.NonceSize()), wire[2:2+int(size)-padding], nil)
		if err != nil {
			t.Fatal(err)
		}
		count++
		chunks = append(chunks, string(plain))
		wire = wire[2+int(size):]
	}
	return chunks
}
func newWireClient(t *testing.T) (*Conn, *wireConn, []byte) {
	t.Helper()
	raw := &wireConn{input: bytes.NewReader(nil)}
	addr, _ := socks5.AddressFromString("example.com:443")
	c, err := newConn(raw, request{address: addr, network: "tcp", cipher: CipherAES128GCM}, wireKey)
	if err != nil {
		t.Fatal(err)
	}
	if raw.writes != 0 {
		t.Fatal("newConn wrote the request header")
	}
	request, _ := parseRequest(t, c.header)
	if request[37] != 1 || string(request[42:53]) != "example.com" {
		t.Fatalf("bad request=%x", request)
	}
	return c, raw, request
}
func responseWire(t *testing.T, request []byte, parts ...[]byte) []byte {
	t.Helper()
	keySum := sha256.Sum256(request[17:33])
	ivSum := sha256.Sum256(request[1:17])
	key, iv := keySum[:16], ivSum[:16]
	aead, _ := NewAesGcm(KDF(key, []byte(KDFSaltConstAEADRespHeaderLenKey))[:16])
	wire := aead.Seal(nil, KDF(iv, []byte(KDFSaltConstAEADRespHeaderLenIV))[:12], []byte{0, 4}, nil)
	aead, _ = NewAesGcm(KDF(key, []byte(KDFSaltConstAEADRespHeaderPayloadKey))[:16])
	wire = append(wire, aead.Seal(nil, KDF(iv, []byte(KDFSaltConstAEADRespHeaderPayloadIV))[:12], []byte{request[33], 0, 0, 0}, nil)...)
	body, _ := NewAesGcm(key)
	mask := NewShakeSizeParser(iv)
	for i, part := range parts {
		padding := int(mask.NextPaddingLen())
		frame := make([]byte, 2+len(part)+body.Overhead()+padding)
		mask.Encode(uint16(len(frame)-2), frame)
		body.Seal(frame[2:2], chunkNonce([16]byte(iv), uint32(i), body.NonceSize()), part, nil)
		wire = append(wire, frame...)
	}
	return wire
}
func TestClientWireAndAuthenticatedHalfClose(t *testing.T) {
	c, raw, request := newWireClient(t)
	payload := bytes.Repeat([]byte("data"), 10000)
	original := bytes.Clone(payload)
	if n, err := c.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write=%d,%v", n, err)
	}
	if !bytes.Equal(payload, original) {
		t.Fatal("mutated caller bytes")
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, wire := parseRequest(t, raw.output.Bytes())
	chunks := openChunks(t, request, wire, 0)
	// One carrier write per chunk: the header shares the first.
	if !bytes.Equal(got, request) || raw.writes != len(chunks) || strings.Join(chunks, "") != string(payload) || chunks[len(chunks)-1] != "" {
		t.Fatal("request framing or half-close signal")
	}
	raw.input = bytes.NewReader(responseWire(t, request, []byte("response after close"), nil))
	reply, err := io.ReadAll(c)
	if err != nil || string(reply) != "response after close" {
		t.Fatalf("ReadAll=%q,%v", reply, err)
	}
}
func TestResponseRejectsMalformedAndUnauthenticatedTerminal(t *testing.T) {
	c, raw, request := newWireClient(t)
	wire := responseWire(t, request, nil)
	// Tamper with the terminal AEAD tag, not the unauthenticated padding.
	mask := NewShakeSizeParser(c.readIV[:])
	padding := int(mask.NextPaddingLen())
	wire[len(wire)-padding-1] ^= 1
	raw.input = bytes.NewReader(wire)
	_, err := c.Read(make([]byte, 1))
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("forged EOF=%v", err)
	}
	_, again := c.Read(make([]byte, 1))
	if again != err {
		t.Fatal("authentication failure was not sticky")
	}
	c, raw, request = newWireClient(t)
	wire = responseWire(t, request, []byte("a"))
	aead, _ := NewAesGcm(KDF(c.responseKey[:], []byte(KDFSaltConstAEADRespHeaderLenKey))[:16])
	short := aead.Seal(nil, KDF(c.readIV[:], []byte(KDFSaltConstAEADRespHeaderLenIV))[:12], []byte{0, 1}, nil)
	copy(wire, short)
	raw.input = bytes.NewReader(wire)
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("accepted undersized response header")
	}
}
func TestFirstOperationCarriesRequestHeader(t *testing.T) {
	for _, tc := range []struct {
		name string
		op   func(*Conn, *wireConn, []byte) error
		body []string // request chunks after the header
	}{
		{"Write", func(c *Conn, _ *wireConn, _ []byte) error { _, err := c.Write([]byte("hello")); return err }, []string{"hello"}},
		{"EmptyWrite", func(c *Conn, _ *wireConn, _ []byte) error { _, err := c.Write(nil); return err }, nil},
		{"CloseWrite", func(c *Conn, _ *wireConn, _ []byte) error { return c.CloseWrite() }, []string{""}},
		{"Read", func(c *Conn, raw *wireConn, request []byte) error {
			raw.input = bytes.NewReader(responseWire(t, request, []byte("reply")))
			p := make([]byte, 8)
			n, err := c.Read(p)
			if err == nil && string(p[:n]) != "reply" {
				err = fmt.Errorf("reply=%q", p[:n])
			}
			return err
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, raw, request := newWireClient(t)
			if err := tc.op(c, raw, request); err != nil {
				t.Fatal(err)
			}
			got, wire := parseRequest(t, raw.output.Bytes())
			if body := openChunks(t, request, wire, 0); raw.writes != 1 || !bytes.Equal(got, request) || !slices.Equal(body, tc.body) {
				t.Fatalf("writes=%d body=%q", raw.writes, body)
			}
		})
	}
}
func TestShortWriteIsStickyIncludingHeader(t *testing.T) {
	c, raw, _ := newWireClient(t)
	raw.short = true
	if _, err := c.Write([]byte("hello")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	writes := raw.writes
	if _, err := c.Write([]byte("retry")); !errors.Is(err, io.ErrShortWrite) || raw.writes != writes {
		t.Fatal("retried partial encrypted frame")
	}
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.ErrShortWrite) || raw.writes != writes {
		t.Fatal("read past an unsent request header")
	}
	c, raw, _ = newWireClient(t)
	raw.short = true
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.ErrShortWrite) || raw.writes != 1 {
		t.Fatalf("flush on read=%v,writes=%d", err, raw.writes)
	}
	if err := c.CloseWrite(); !errors.Is(err, io.ErrShortWrite) || raw.writes != 1 {
		t.Fatal("retried a failed request header")
	}
}

// A peer may reply after part of the first Write and read on only once the
// client has read that reply.
func TestReadDoesNotWaitForBlockedFirstWrite(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	addr, _ := socks5.AddressFromString("example.com:443")
	c, err := newConn(local, request{address: addr, network: "tcp", cipher: CipherAES128GCM}, wireKey)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	request, _ := parseRequest(t, c.header)
	go c.Write(make([]byte, 64<<10))
	if _, err := io.ReadFull(peer, make([]byte, 1<<10)); err != nil {
		t.Fatal(err)
	}
	read := make(chan string, 1)
	go func() {
		reply := make([]byte, 5)
		n, _ := io.ReadFull(c, reply)
		read <- string(reply[:n])
	}()
	_ = peer.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := peer.Write(responseWire(t, request, []byte("reply"))); err != nil {
		t.Fatalf("Read waited for the first Write: %v", err)
	}
	if got := <-read; got != "reply" {
		t.Fatalf("reply=%q", got)
	}
}

type pipeDialer struct{ conn net.Conn }

func (d pipeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}
func (pipeDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.ErrUnsupported
}
func TestDialDefersHeaderAndPacketAddressBounds(t *testing.T) {
	raw := &wireConn{input: bytes.NewReader(nil)}
	d, err := NewDialer(pipeDialer{raw}, protocol.Header{Password: "01234567-89ab-cdef-0123-456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.DialContext(t.Context(), "tcp", "example.com:80"); err != nil || raw.writes != 0 {
		t.Fatalf("Dial=%v,writes=%d", err, raw.writes)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if conn, err := d.DialContext(ctx, "tcp", "example.com:80"); conn != nil || !errors.Is(err, context.Canceled) || !raw.closed {
		t.Fatalf("canceled Dial=%v,%v,closed=%v", conn, err, raw.closed)
	}
	stale := errors.New("stale carrier")
	raw.closed, raw.lease = false, netproxy.NewLease(netproxy.NewResourceRef())
	raw.lease.Invalidate(stale)
	if _, err := d.DialContext(t.Context(), "tcp", "example.com:80"); !errors.Is(err, stale) || !raw.closed {
		t.Fatalf("stale Dial=%v,closed=%v", err, raw.closed)
	}
	for _, data := range [][]byte{nil, {1}, {2, 1, 2}, {3}} {
		if _, _, err := extractPacketAddress(data); err == nil {
			t.Fatalf("accepted malformed address %x", data)
		}
	}
	encoded, err := appendPacketAddress(nil, netproxy.NewAddr("udp", "[2001:db8::1]:53"))
	if err != nil {
		t.Fatal(err)
	}
	from, payload, err := extractPacketAddress(append(encoded, 1, 2))
	if err != nil || from.String() != "[2001:db8::1]:53" || len(payload) != 2 {
		t.Fatalf("address roundtrip=%v,%x,%v", from, payload, err)
	}
}

func TestNonceBoundaryIncludesTerminalFrame(t *testing.T) {
	c, raw, request := newWireClient(t)
	c.writeCount = 65535
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_, wire := parseRequest(t, raw.output.Bytes())
	if chunks := openChunks(t, request, wire, 65535); !slices.Equal(chunks, []string{""}) {
		t.Fatalf("last nonce terminal=%q", chunks)
	}
	c, raw, request = newWireClient(t)
	c.writeCount = 65535
	if _, err := c.Write([]byte("last")); err != nil {
		t.Fatal(err)
	}
	writes := raw.writes
	if err := c.CloseWrite(); err == nil || raw.writes != writes {
		t.Fatal("wrapped request nonce for terminal")
	}
	c.responseReady = true
	c.readCount = 65535
	body, _ := NewAesGcm(c.responseKey[:])
	mask := NewShakeSizeParser(c.readIV[:])
	padding := int(mask.NextPaddingLen())
	wire = make([]byte, 2+16+padding)
	mask.Encode(uint16(len(wire)-2), wire)
	body.Seal(wire[2:2], chunkNonce(c.readIV, 65535, body.NonceSize()), nil, nil)
	raw.input = bytes.NewReader(wire)
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) || c.readCount != 65536 {
		t.Fatalf("last response terminal=%v,count=%d", err, c.readCount)
	}
	other, _, _ := newWireClient(t)
	if _, err := other.Write([]byte("independent")); err != nil {
		t.Fatal(err)
	}
}

func TestDeadlineResumesPartialEncryptedFrame(t *testing.T) {
	for _, cut := range []int{5, 43} {
		t.Run(fmt.Sprint(cut), func(t *testing.T) {
			c, _, request := newWireClient(t)
			if _, err := c.Write(nil); err != nil {
				t.Fatal(err)
			}
			wire := responseWire(t, request, []byte("reply"), nil)
			local, peer := net.Pipe()
			defer local.Close()
			defer peer.Close()
			c.Conn = local
			c.reader = bufio.NewReaderSize(local, MaxChunkSize)
			first := make(chan error, 1)
			go func() { _, err := peer.Write(wire[:cut]); first <- err }()
			_ = c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
			_, err := c.Read(make([]byte, 10))
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() {
				t.Fatalf("deadline=%v", err)
			}
			if err := <-first; err != nil {
				t.Fatal(err)
			}
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			go func() { _, _ = peer.Write(wire[cut:]) }()
			got, err := io.ReadAll(c)
			if err != nil || string(got) != "reply" {
				t.Fatalf("resumed=%q,%v", got, err)
			}
		})
	}
}

func TestBoundPacketAddressResolvesDomainDuringDial(t *testing.T) {
	raw := &wireConn{input: bytes.NewReader(nil)}
	d, err := NewDialer(pipeDialer{raw}, protocol.Header{Password: "01234567-89ab-cdef-0123-456789abcdef", Flags: protocol.Flags_VMess_UsePacketAddr})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "udp", "localhost:53")
	if err != nil {
		t.Fatal(err)
	}
	bound := conn.(*netproxy.BindPacketConn)
	if _, err := netip.ParseAddrPort(bound.Address.String()); err != nil {
		t.Fatalf("bound domain was not resolved: %v", bound.Address)
	}
	if n, err := conn.Write([]byte("packet")); err != nil || n != 6 || raw.writes != 1 {
		t.Fatalf("bound Write=%d,%v,writes=%d", n, err, raw.writes)
	}
	pc, err := d.ListenPacket(ctx, "localhost:53")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pc.WriteTo([]byte("packet"), netproxy.NewAddr("udp", "localhost:53")); err == nil || raw.writes != 1 {
		t.Fatal("WriteTo silently resolved a domain")
	}
	if _, _, err := pc.ReadFrom(make([]byte, 1)); !errors.Is(err, io.EOF) || raw.writes != 1 {
		t.Fatalf("ReadFrom=%v,writes=%d", err, raw.writes)
	}
}
