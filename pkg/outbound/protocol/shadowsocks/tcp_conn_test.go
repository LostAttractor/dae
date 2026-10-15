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

func TestTCPConnBufferedPayloadLifecycle(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	conn := &TCPConn{
		Conn:    client,
		readBuf: pool.GetBuffer(16),
	}
	copy(conn.readBuf, "0123456789abcdef")

	buf := make([]byte, 10)
	if n, err := conn.Read(buf); err != nil || n != len(buf) {
		t.Fatalf("first Read() = %d, %v", n, err)
	}
	if conn.readBuf == nil {
		t.Fatal("partial read released its payload")
	}
	if n, err := conn.Read(buf); err != nil || n != 6 {
		t.Fatalf("second Read() = %d, %v", n, err)
	}
	if conn.readBuf != nil || conn.readOffset != 0 {
		t.Fatal("completed read retained its payload")
	}
	conn.readBuf = pool.GetBuffer(16)
	conn.readOffset = 4
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if conn.readBuf != nil || conn.readOffset != 0 {
		t.Fatal("Close retained its payload")
	}

}

func TestTCPConnCloseUnblocksRead(t *testing.T) {
	underlay := &interruptingCloseConn{
		readStarted: make(chan struct{}),
		closed:      make(chan struct{}),
	}
	conn := &TCPConn{
		Conn:       underlay,
		cipherConf: &ciphers.CipherConf{SaltLen: 1},
	}
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
		onceWrite:   true,
	}

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
		onceWrite:   true,
	}
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
	if conn.onceWrite {
		t.Fatal("failed address encoding marked the first write complete")
	}
}

func TestTCPConnSealWritesValidChunks(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	conn := &TCPConn{
		cipherWrite: aead,
		nonceWrite:  make([]byte, aead.NonceSize()),
	}
	payload := bytes.Repeat([]byte("x"), TCPChunkMaxLen+17)
	var sealed bytes.Buffer
	conn.seal(&sealed, payload)

	nonce := make([]byte, aead.NonceSize())
	var plaintext []byte
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
	}
	if !bytes.Equal(plaintext, payload) {
		t.Fatal("decrypted chunks do not match payload")
	}
}

type readStep struct {
	data []byte
	err  error
}
type interruptedReader struct {
	shortWriteConn
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

func TestTCPConnPartialSaltTimeoutIsSticky(t *testing.T) {
	timeout := &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
	for _, received := range []int{0, 5} {
		t.Run(strconv.Itoa(received), func(t *testing.T) {
			raw := &interruptedReader{steps: []readStep{{make([]byte, received), timeout}}}
			c := &TCPConn{Conn: raw, cipherConf: ciphers.AeadCiphersConf["aes-128-gcm"]}
			if _, err := c.Read(make([]byte, 1)); err != timeout {
				t.Fatal(err)
			}
			_, err := c.Read(make([]byte, 1))
			if received > 0 {
				if err != timeout || raw.reads != 1 {
					t.Fatal("partial salt was read twice")
				}
			} else if raw.reads != 2 {
				t.Fatal("zero-byte timeout made aligned reader unusable")
			}
		})
	}
}

func TestTCPConnPayloadTimeoutAfterLengthIsSticky(t *testing.T) {
	block, _ := aes.NewCipher(make([]byte, 16))
	aead, _ := cipher.NewGCM(block)
	header := aead.Seal(nil, make([]byte, 12), []byte{0, 1}, nil)
	raw := &interruptedReader{steps: []readStep{{header, nil}, {nil, os.ErrDeadlineExceeded}}}
	c := &TCPConn{Conn: raw, cipherConf: ciphers.AeadCiphersConf["aes-128-gcm"], cipherRead: aead, nonceRead: make([]byte, 12), onceRead: true}
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	calls := raw.reads
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) || raw.reads != calls {
		t.Fatal("payload timeout retried as a length frame")
	}
}

type pipeParent struct{ conn net.Conn }

func (p pipeParent) DialContext(context.Context, string, string) (net.Conn, error) {
	return p.conn, nil
}
func (p pipeParent) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("unused")
}

func TestDialContextSendsRequestBeforeApplicationWrite(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		salt := make([]byte, 16)
		if _, err := io.ReadFull(server, salt); err != nil {
			done <- err
			return
		}
		key := common.EVPBytesToKey("password", 16)
		subkey := make([]byte, 16)
		if _, err := io.ReadFull(hkdf.New(sha1.New, key, salt, []byte("ss-subkey")), subkey); err != nil {
			done <- err
			return
		}
		block, _ := aes.NewCipher(subkey)
		aead, _ := cipher.NewGCM(block)
		nonce := make([]byte, 12)
		encrypted := make([]byte, 18)
		if _, err := io.ReadFull(server, encrypted); err != nil {
			done <- err
			return
		}
		length, err := aead.Open(nil, nonce, encrypted, nil)
		if err != nil {
			done <- err
			return
		}
		encrypted = make([]byte, int(binary.BigEndian.Uint16(length))+16)
		if _, err := io.ReadFull(server, encrypted); err != nil {
			done <- err
			return
		}
		nonce[0] = 1
		plain, err := aead.Open(nil, nonce, encrypted, nil)
		if err != nil {
			done <- err
			return
		}
		addr, err := socks5.ReadAddrInfo(bytes.NewReader(plain))
		if err == nil && (addr.Hostname != "example.com" || addr.Port != 443) {
			err = errors.New("incorrect target")
		}
		done <- err
	}()
	dialer, err := NewDialer(pipeParent{client}, protocol.Header{Cipher: "aes-128-gcm", Password: "password", ProxyAddress: "proxy:443"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDialContextCancellationClosesIncompleteRequest(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	dialer, err := NewDialer(pipeParent{client}, protocol.Header{Cipher: "aes-128-gcm", Password: "password", ProxyAddress: "proxy:443"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if conn, err := dialer.DialContext(ctx, "tcp", "example.com:443"); conn != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled dial=%v %v", conn, err)
	}
	if _, err := client.Write([]byte("retry")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("partial request kept carrier open: %v", err)
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
	if n, addr, err := c.ReadFrom(tiny); err != nil || n != 2 || string(tiny) != "lo" || addr.String() != "127.0.0.1:53" {
		t.Fatalf("ReadFrom=%d %v %v", n, addr, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
