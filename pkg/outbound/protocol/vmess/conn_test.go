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
}

func (c *wireConn) Read(p []byte) (int, error) { return c.input.Read(p) }
func (c *wireConn) Write(p []byte) (int, error) {
	c.writes++
	if c.short {
		return len(p) - 1, nil
	}
	return c.output.Write(p)
}
func (c *wireConn) Close() error                { return nil }
func (c *wireConn) SetDeadline(time.Time) error { return nil }
func newWireClient(t *testing.T) (*Conn, *wireConn, []byte) {
	t.Helper()
	raw := &wireConn{input: bytes.NewReader(nil)}
	addr, _ := socks5.AddressFromString("example.com:443")
	key := bytes.Repeat([]byte{7}, 16)
	c, err := newConn(raw, request{address: addr, network: "tcp", cipher: CipherAES128GCM}, key)
	if err != nil {
		t.Fatal(err)
	}
	wire := raw.output.Bytes()
	aead, _ := NewAesGcm(KDF(key, []byte(KDFSaltConstVMessHeaderPayloadLengthAEADKey), wire[:16], wire[34:42])[:16])
	size, err := aead.Open(nil, KDF(key, []byte(KDFSaltConstVMessHeaderPayloadLengthAEADIV), wire[:16], wire[34:42])[:12], wire[16:34], wire[:16])
	if err != nil {
		t.Fatal(err)
	}
	aead, _ = NewAesGcm(KDF(key, []byte(KDFSaltConstVMessHeaderPayloadAEADKey), wire[:16], wire[34:42])[:16])
	request, err := aead.Open(nil, KDF(key, []byte(KDFSaltConstVMessHeaderPayloadAEADIV), wire[:16], wire[34:42])[:12], wire[42:], wire[:16])
	if err != nil {
		t.Fatal(err)
	}
	if len(request) != int(binary.BigEndian.Uint16(size)) || request[37] != 1 || string(request[42:53]) != "example.com" {
		t.Fatalf("bad request=%x", request)
	}
	sum := fnv.New32a()
	sum.Write(request[:len(request)-4])
	if binary.BigEndian.Uint32(request[len(request)-4:]) != sum.Sum32() {
		t.Fatal("request checksum")
	}
	raw.output.Reset()
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
	body, _ := NewAesGcm(request[17:33])
	mask := NewShakeSizeParser(request[1:17])
	wire := raw.output.Bytes()
	var decoded []byte
	count := uint32(0)
	terminal := false
	for len(wire) > 0 {
		padding := int(mask.NextPaddingLen())
		size, _ := mask.Decode(wire[:2])
		data := wire[2 : 2+int(size)-padding]
		plain, err := body.Open(nil, chunkNonce([16]byte(request[1:17]), count, body.NonceSize()), data, nil)
		if err != nil {
			t.Fatal(err)
		}
		count++
		decoded = append(decoded, plain...)
		terminal = len(plain) == 0
		wire = wire[2+int(size):]
	}
	if !bytes.Equal(decoded, payload) || !terminal {
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
func TestShortWriteStopsVMessNonceProgress(t *testing.T) {
	c, raw, _ := newWireClient(t)
	raw.short = true
	if _, err := c.Write([]byte("hello")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	writes := raw.writes
	if _, err := c.Write([]byte("retry")); !errors.Is(err, io.ErrShortWrite) || raw.writes != writes {
		t.Fatal("retried partial encrypted frame")
	}
}

type pipeDialer struct{ conn net.Conn }

func (d pipeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}
func (pipeDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.ErrUnsupported
}
func TestDialHeaderCancellationAndPacketAddressBounds(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	d, err := NewDialer(pipeDialer{local}, protocol.Header{Password: "01234567-89ab-cdef-0123-456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timer := time.AfterFunc(20*time.Millisecond, cancel)
	defer timer.Stop()
	if conn, err := d.DialContext(ctx, "tcp", "example.com:80"); conn != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Dial=%v,%v", conn, err)
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
	body, _ := NewAesGcm(request[17:33])
	mask := NewShakeSizeParser(request[1:17])
	padding := int(mask.NextPaddingLen())
	wire := raw.output.Bytes()
	plain, err := body.Open(nil, chunkNonce([16]byte(request[1:17]), 65535, body.NonceSize()), wire[2:len(wire)-padding], nil)
	if err != nil || len(plain) != 0 {
		t.Fatalf("last nonce terminal=%x,%v", plain, err)
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
	body, _ = NewAesGcm(c.responseKey[:])
	mask = NewShakeSizeParser(c.readIV[:])
	padding = int(mask.NextPaddingLen())
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
	if n, err := conn.Write([]byte("packet")); err != nil || n != 6 {
		t.Fatalf("bound Write=%d,%v", n, err)
	}
	pc, err := d.ListenPacket(ctx, "localhost:53")
	if err != nil {
		t.Fatal(err)
	}
	writes := raw.writes
	if _, err := pc.WriteTo([]byte("packet"), netproxy.NewAddr("udp", "localhost:53")); err == nil || writes != raw.writes {
		t.Fatal("WriteTo silently resolved a domain")
	}
}
