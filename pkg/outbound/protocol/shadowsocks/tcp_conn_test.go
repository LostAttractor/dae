package shadowsocks

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"golang.org/x/crypto/hkdf"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/common"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
)

type interruptingCloseConn struct {
	readStarted chan struct{}
	closed      chan struct{}
	startOnce   sync.Once
	closeOnce   sync.Once
}

func (c *interruptingCloseConn) Read([]byte) (int, error) {
	c.startOnce.Do(func() { close(c.readStarted) })
	<-c.closed
	return 0, net.ErrClosed
}

func (c *interruptingCloseConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *interruptingCloseConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
func (c *interruptingCloseConn) LocalAddr() net.Addr         { return nil }
func (c *interruptingCloseConn) RemoteAddr() net.Addr        { return nil }
func (c *interruptingCloseConn) SetDeadline(time.Time) error { return nil }
func (c *interruptingCloseConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *interruptingCloseConn) SetWriteDeadline(time.Time) error {
	return nil
}

type shortWriteConn struct {
	bytes.Buffer
	writes int
}

func (c *shortWriteConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *shortWriteConn) Close() error                     { return nil }
func (c *shortWriteConn) LocalAddr() net.Addr              { return nil }
func (c *shortWriteConn) RemoteAddr() net.Addr             { return nil }
func (c *shortWriteConn) SetDeadline(time.Time) error      { return nil }
func (c *shortWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (c *shortWriteConn) SetWriteDeadline(time.Time) error { return nil }
func (c *shortWriteConn) Write(b []byte) (int, error) {
	c.writes++
	n := len(b) / 2
	c.Buffer.Write(b[:n])
	return n, nil
}

type fullWriteErrorConn struct {
	shortWriteConn
	err error
}

func (c *fullWriteErrorConn) Write(b []byte) (int, error) {
	c.writes++
	c.Buffer.Write(b)
	err := c.err
	c.err = nil
	return len(b), err
}

type fixedSaltGenerator struct {
	salt []byte
}

func (g *fixedSaltGenerator) Get() []byte {
	salt := pool.GetBuffer(len(g.salt))
	copy(salt, g.salt)
	return salt
}

func TestTCPConnCloseUnblocksRead(t *testing.T) {
	underlay := &interruptingCloseConn{
		readStarted: make(chan struct{}),
		closed:      make(chan struct{}),
	}
	conn := NewTCPConn(underlay, ciphers.AeadCiphersConf["aes-128-gcm"], make([]byte, 16), RandomSaltGenerator(16), nil)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_, _ = conn.Read(make([]byte, 1))
	}()
	<-underlay.readStarted

	closeDone := make(chan error, 1)
	go func() { closeDone <- conn.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock Read")
	}

	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("Read remained blocked after Close")
	}
}

func TestTCPConnWriteRejectsShortUnderlayWrite(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	underlay := &shortWriteConn{}
	conn := &TCPConn{
		Conn:        underlay,
		cipherWrite: aead,
		nonceWrite:  make([]byte, aead.NonceSize()),
	}
	conn.first.Done(nil)

	if n, err := conn.Write([]byte("payload")); n != 0 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Write() = %d, %v; want 0, %v", n, err, io.ErrShortWrite)
	}
	if n, err := conn.Write([]byte("retry")); n != 0 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("second Write() = %d, %v; want 0, %v", n, err, io.ErrShortWrite)
	}
	if underlay.writes != 1 {
		t.Fatalf("underlay writes = %d, want 1", underlay.writes)
	}
}

func TestTCPConnWriteKeepsAlignedStreamUsableAfterFullWriteError(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	writeErr := errors.New("write failed after consuming buffer")
	underlay := &fullWriteErrorConn{err: writeErr}
	conn := &TCPConn{
		Conn:        underlay,
		cipherWrite: aead,
		nonceWrite:  make([]byte, aead.NonceSize()),
	}
	conn.first.Done(nil)
	payload := []byte("payload")

	if n, err := conn.Write(payload); n != len(payload) || !errors.Is(err, writeErr) {
		t.Fatalf("Write() = %d, %v; want %d, %v", n, err, len(payload), writeErr)
	}
	retry := []byte("retry")
	if n, err := conn.Write(retry); n != len(retry) || err != nil {
		t.Fatalf("second Write() = %d, %v; want %d, nil", n, err, len(retry))
	}
	if underlay.writes != 2 {
		t.Fatalf("underlay writes = %d, want 2", underlay.writes)
	}
}

func TestTCPConnWriteRejectsInvalidAddressBeforeWriting(t *testing.T) {
	underlay := &shortWriteConn{}
	conn := &TCPConn{
		Conn:       underlay,
		addr:       &socks5.AddressInfo{Type: socks5.AddressTypeDomain, Hostname: strings.Repeat("x", 256)},
		cipherConf: ciphers.AeadCiphersConf["aes-128-gcm"],
		masterKey:  make([]byte, 16),
		sg:         &fixedSaltGenerator{salt: make([]byte, 16)},
		nonceWrite: make([]byte, 12),
	}

	if n, err := conn.Write([]byte("payload")); n != 0 || err == nil {
		t.Fatalf("Write() = %d, %v; want address error", n, err)
	}
	if underlay.writes != 0 {
		t.Fatalf("underlay writes = %d, want 0", underlay.writes)
	}
	if conn.first.Err() == nil {
		t.Fatal("failed address encoding not kept")
	}
}

func TestTCPConnWriteBuffersSealsWholeChunks(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	underlay := &fullWriteErrorConn{}
	conn := &TCPConn{
		Conn:        underlay,
		cipherWrite: aead,
		nonceWrite:  make([]byte, aead.NonceSize()),
	}
	conn.first.Done(nil)
	// An 8-byte frame header, then payload crossing a chunk boundary.
	v := [][]byte{[]byte("header.."), bytes.Repeat([]byte("x"), TCPChunkMaxLen), nil, []byte("tail")}
	var payload []byte
	for _, b := range v {
		payload = append(payload, b...)
	}
	if n, err := conn.WriteBuffers(v); n != len(payload) || err != nil {
		t.Fatalf("WriteBuffers() = %d, %v", n, err)
	}
	if underlay.writes != 1 {
		t.Fatalf("underlay writes = %d, want 1", underlay.writes)
	}

	sealed := &underlay.Buffer
	nonce := make([]byte, aead.NonceSize())
	var plaintext []byte
	var chunks []int
	for sealed.Len() > 0 {
		lengthCiphertext := sealed.Next(2 + aead.Overhead())
		lengthBytes, err := aead.Open(nil, nonce, lengthCiphertext, nil)
		if err != nil {
			t.Fatal(err)
		}
		common.BytesIncLittleEndian(nonce)
		chunkLength := int(binary.BigEndian.Uint16(lengthBytes))
		chunkCiphertext := sealed.Next(chunkLength + aead.Overhead())
		chunk, err := aead.Open(nil, nonce, chunkCiphertext, nil)
		if err != nil {
			t.Fatal(err)
		}
		common.BytesIncLittleEndian(nonce)
		plaintext = append(plaintext, chunk...)
		chunks = append(chunks, chunkLength)
	}
	if !bytes.Equal(plaintext, payload) {
		t.Fatal("decrypted chunks do not match payload")
	}
	if len(chunks) != 2 || chunks[0] != TCPChunkMaxLen {
		t.Fatalf("chunk lengths = %v, want one full chunk and the rest", chunks)
	}
	if len(v[1]) != TCPChunkMaxLen {
		t.Fatal("WriteBuffers consumed the caller's buffers")
	}
}

type readStep struct {
	data []byte
	err  error
}
type interruptedReader struct {
	fullWriteErrorConn
	steps []readStep
	reads int
}

func (c *interruptedReader) Read(b []byte) (int, error) {
	c.reads++
	if len(c.steps) == 0 {
		return 0, io.EOF
	}
	step := c.steps[0]
	c.steps = c.steps[1:]
	return copy(b, step.data), step.err
}

// Buffered ciphertext survives a timeout anywhere, so a retry resumes the
// salt, a length chunk or a payload chunk whose length is already opened.
func TestTCPConnTimeoutResumesInsideFrames(t *testing.T) {
	payload := []byte("resumed after timeout")
	key, wire := responseStream(t, "aes-128-gcm", payload, 2)
	timeout := &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
	for _, cut := range []int{0, 5, 16, 16 + 7, 16 + 18, 16 + 18 + 9, len(wire) - 3} {
		t.Run(strconv.Itoa(cut), func(t *testing.T) {
			raw := &interruptedReader{steps: []readStep{{wire[:cut], timeout}, {wire[cut:], nil}}}
			c := NewTCPConn(raw, ciphers.AeadCiphersConf["aes-128-gcm"], key, RandomSaltGenerator(16), nil)
			got := make([]byte, 0, 2*len(payload))
			buf := make([]byte, len(payload))
			for len(got) < cap(got) {
				n, err := c.Read(buf)
				got = append(got, buf[:n]...)
				if err != nil && err != timeout {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(got, bytes.Repeat(payload, 2)) || raw.reads != 2 {
				t.Fatalf("resumed stream = %q after %d reads", got, raw.reads)
			}
		})
	}
}

type pipeParent struct{ conn net.Conn }

func (p pipeParent) DialContext(context.Context, string, string) (net.Conn, error) {
	return p.conn, nil
}
func (p pipeParent) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("unused")
}

// peerConn records carrier writes, serves response only after the client has
// written and notes how many writes preceded each half-close.
type peerConn struct {
	fullWriteErrorConn
	response bytes.Reader
	finAt    []int
}

func (c *peerConn) Read(p []byte) (int, error) {
	if c.writes == 0 {
		return 0, errors.New("read before request")
	}
	return c.response.Read(p)
}
func (c *peerConn) CloseWrite() error { c.finAt = append(c.finAt, c.writes); return nil }

// openRequest decrypts a whole aes-128-gcm client stream as the server would.
func openRequest(t *testing.T, key, wire []byte) (*socks5.AddressInfo, []byte) {
	t.Helper()
	subkey := make([]byte, 16)
	if _, err := io.ReadFull(hkdf.New(sha1.New, key, wire[:16], []byte("ss-subkey")), subkey); err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(subkey)
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	wire = wire[16:]
	open := func(size int) []byte {
		t.Helper()
		plain, err := aead.Open(nil, nonce, wire[:size+16], nil)
		if err != nil {
			t.Fatal(err)
		}
		wire = wire[size+16:]
		common.BytesIncLittleEndian(nonce)
		return plain
	}
	var plain []byte
	for len(wire) > 0 {
		plain = append(plain, open(int(binary.BigEndian.Uint16(open(2))))...)
	}
	reader := bytes.NewReader(plain)
	addr, err := socks5.ReadAddrInfo(reader)
	if err != nil {
		t.Fatal(err)
	}
	return addr, plain[len(plain)-reader.Len():]
}

func TestDialContextDefersRequestToFirstWrite(t *testing.T) {
	raw := new(peerConn)
	dialer, err := NewDialer(pipeParent{raw}, protocol.Header{Cipher: "aes-128-gcm", Password: "password", ProxyAddress: "proxy:443"})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.DialContext(t.Context(), "tcp", "example.com:443")
	if err != nil || raw.writes != 0 {
		t.Fatalf("dial wrote %d times: %v", raw.writes, err)
	}
	if n, err := conn.Write([]byte("payload")); n != 7 || err != nil {
		t.Fatalf("Write() = %d, %v", n, err)
	}
	addr, payload := openRequest(t, common.EVPBytesToKey("password", 16), raw.Bytes())
	if raw.writes != 1 || addr.Hostname != "example.com" || addr.Port != 443 || string(payload) != "payload" {
		t.Fatalf("request %v %q in %d writes", addr, payload, raw.writes)
	}
}

func TestDialContextCanceledClosesCarrier(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	dialer, err := NewDialer(pipeParent{client}, protocol.Header{Cipher: "aes-128-gcm", Password: "password", ProxyAddress: "proxy:443"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if conn, err := dialer.DialContext(ctx, "tcp", "example.com:443"); conn != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled dial=%v %v", conn, err)
	}
	if _, err := client.Write([]byte("retry")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("canceled dial kept carrier open: %v", err)
	}
}

func TestTCPConnReadSendsRequestFirst(t *testing.T) {
	key, response := responseStream(t, "aes-128-gcm", []byte("pong"), 1)
	raw := new(peerConn)
	raw.response.Reset(response)
	target, _ := socks5.AddressFromString("example.com:443")
	conn := NewTCPConn(raw, ciphers.AeadCiphersConf["aes-128-gcm"], key, RandomSaltGenerator(16), target)
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "pong" {
		t.Fatalf("Read() = %q, %v", got, err)
	}
	if addr, payload := openRequest(t, key, raw.Bytes()); raw.writes != 1 || addr.Hostname != "example.com" || len(payload) != 0 {
		t.Fatalf("request %v %q in %d writes", addr, payload, raw.writes)
	}
}

func TestTCPConnCloseWriteSendsRequestFirst(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 16)
	target, _ := socks5.AddressFromString("example.com:443")
	for _, addr := range []*socks5.AddressInfo{target, nil} {
		raw := new(peerConn)
		conn := NewTCPConn(raw, ciphers.AeadCiphersConf["aes-128-gcm"], key, RandomSaltGenerator(16), addr).(*TCPConn)
		if err := conn.CloseWrite(); err != nil || !slices.Equal(raw.finAt, []int{1}) {
			t.Fatalf("CloseWrite() = %v after writes %v", err, raw.finAt)
		}
		if addr == nil {
			// Without a destination the header is the salt.
			if raw.Len() != 16 {
				t.Fatalf("encryption-only header is %d bytes", raw.Len())
			}
			continue
		}
		if got, payload := openRequest(t, key, raw.Bytes()); got.Hostname != "example.com" || len(payload) != 0 {
			t.Fatalf("request %v %q", got, payload)
		}
	}
}

// A peer may reply after part of the first Write and read on only once the
// client has read that reply.
func TestTCPConnReadDoesNotWaitForBlockedFirstWrite(t *testing.T) {
	key, response := responseStream(t, "aes-128-gcm", []byte("reply"), 1)
	local, peer := net.Pipe()
	defer peer.Close()
	target, _ := socks5.AddressFromString("example.com:443")
	conn := NewTCPConn(local, ciphers.AeadCiphersConf["aes-128-gcm"], key, RandomSaltGenerator(16), target)
	defer conn.Close()
	go conn.Write(make([]byte, 64<<10))
	if _, err := io.ReadFull(peer, make([]byte, 1<<10)); err != nil {
		t.Fatal(err)
	}
	read := make(chan string, 1)
	go func() {
		reply := make([]byte, 5)
		n, _ := io.ReadFull(conn, reply)
		read <- string(reply[:n])
	}()
	_ = peer.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := peer.Write(response); err != nil {
		t.Fatalf("Read waited for the first Write: %v", err)
	}
	if got := <-read; got != "reply" {
		t.Fatalf("reply=%q", got)
	}
}

func TestTCPConnFailedRequestIsSticky(t *testing.T) {
	raw := new(shortWriteConn)
	target, _ := socks5.AddressFromString("example.com:443")
	conn := NewTCPConn(raw, ciphers.AeadCiphersConf["aes-128-gcm"], make([]byte, 16), RandomSaltGenerator(16), target).(*TCPConn)
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Read() = %v", err)
	}
	if _, err := conn.Write([]byte("retry")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Write() = %v", err)
	}
	if err := conn.CloseWrite(); !errors.Is(err, io.ErrShortWrite) || raw.writes != 1 {
		t.Fatalf("CloseWrite() = %v after %d writes", err, raw.writes)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("second Read() = %v", err)
	}
}

func TestTCPConnFullFirstWriteErrorIsSticky(t *testing.T) {
	want := errors.New("carrier failed after consuming the request")
	raw := &fullWriteErrorConn{err: want}
	target, _ := socks5.AddressFromString("example.com:443")
	c := NewTCPConn(raw, ciphers.AeadCiphersConf["aes-128-gcm"], make([]byte, 16), RandomSaltGenerator(16), target).(*TCPConn)
	if n, err := c.WriteBuffers([][]byte{[]byte("one"), []byte("two")}); n != 6 || err != want {
		t.Fatalf("first WriteBuffers = %d, %v", n, err)
	}
	if _, err := c.Write([]byte("retry")); err != want {
		t.Fatalf("second Write = %v", err)
	}
	if _, err := c.Read(make([]byte, 1)); err != want {
		t.Fatalf("Read = %v", err)
	}
	if err := c.CloseWrite(); err != want || raw.writes != 1 {
		t.Fatalf("CloseWrite = %v after %d writes", err, raw.writes)
	}
}

func TestUDPShortCallerBufferStillAuthenticatesWholePacket(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	defer client.Close()
	conf := ciphers.AeadCiphersConf["aes-128-gcm"]
	key := bytes.Repeat([]byte{5}, 16)
	salt := bytes.Repeat([]byte{6}, 16)
	subkey := make([]byte, 16)
	io.ReadFull(hkdf.New(sha1.New, key, salt, []byte("ss-subkey")), subkey)
	block, _ := aes.NewCipher(subkey)
	aead, _ := cipher.NewGCM(block)
	plaintext := append([]byte{1, 127, 0, 0, 1, 0, 53}, []byte("long answer")...)
	wire := aead.Seal(append([]byte(nil), salt...), make([]byte, 12), plaintext, nil)
	done := make(chan error, 1)
	go func() { _, err := server.Write(wire); done <- err }()
	c := NewUdpConn(client, conf, key, &fixedSaltGenerator{salt: salt})
	tiny := make([]byte, 2)
	if n, addr, err := c.ReadFrom(tiny); !errors.Is(err, io.ErrShortBuffer) || n != 2 || string(tiny) != "lo" || addr.String() != "127.0.0.1:53" {
		t.Fatalf("ReadFrom=%d %v %v", n, addr, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type writeCountingReader struct {
	net.Conn
	io.Reader
	writes int
}

func (c *writeCountingReader) Read(b []byte) (int, error) { return c.Reader.Read(b) }
func (c *writeCountingReader) Write(b []byte) (int, error) {
	c.writes++
	return len(b), nil
}

// Without a destination the enclosing protocol owns the request, so a Read
// before any write sends nothing; a Trojan UDP reader must not emit the salt.
func TestTransportReadLeavesRequestToEnclosingProtocol(t *testing.T) {
	payload := []byte("response")
	key, wire := responseStream(t, "aes-128-gcm", payload, 1)
	carrier := &writeCountingReader{Reader: bytes.NewReader(wire)}
	c := NewTCPConn(carrier, ciphers.AeadCiphersConf["aes-128-gcm"], key, RandomSaltGenerator(16), nil)
	buf := make([]byte, len(payload))
	if n, err := io.ReadFull(c, buf); err != nil || !bytes.Equal(buf[:n], payload) || carrier.writes != 0 {
		t.Fatalf("Read = %q, %v; carrier writes = %d", buf[:n], err, carrier.writes)
	}
}
