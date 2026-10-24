package aeadframe

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/common"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
)

func testAEAD(t testing.TB) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return aead
}

// seal frames payloads as a peer does: a length chunk, then the payload chunk.
func seal(aead cipher.AEAD, payloads ...[]byte) []byte {
	nonce := make([]byte, aead.NonceSize())
	var wire []byte
	for _, payload := range payloads {
		wire = aead.Seal(wire, nonce, binary.BigEndian.AppendUint16(nil, uint16(len(payload))), nil)
		common.BytesIncLittleEndian(nonce)
		wire = aead.Seal(wire, nonce, payload, nil)
		common.BytesIncLittleEndian(nonce)
	}
	return wire
}

func testPayloads(sizes ...int) [][]byte {
	payloads := make([][]byte, len(sizes))
	for i, size := range sizes {
		payloads[i] = bytes.Repeat([]byte{byte('a' + i)}, size)
	}
	return payloads
}

type step struct {
	data []byte
	err  error
}

// scriptConn returns each step's data, then its error with the last byte.
type scriptConn struct {
	net.Conn
	steps []step
	reads int
}

func (c *scriptConn) Read(p []byte) (int, error) {
	c.reads++
	if len(c.steps) == 0 {
		return 0, io.EOF
	}
	s := &c.steps[0]
	n := copy(p, s.data)
	s.data = s.data[n:]
	if len(s.data) > 0 {
		return n, nil
	}
	err := s.err
	c.steps = c.steps[1:]
	return n, err
}

func pieces(wire []byte, size int) []step {
	var steps []step
	for len(wire) > 0 {
		n := min(size, len(wire))
		steps = append(steps, step{data: wire[:n]})
		wire = wire[n:]
	}
	return steps
}

func newTestReader(t testing.TB, conn net.Conn) *Reader {
	aead := testAEAD(t)
	r := &Reader{Conn: conn}
	r.Start(aead, make([]byte, aead.NonceSize()), -1)
	return r
}

// readAll collects payload until err is neither nil nor tolerated.
func readAll(r *Reader, tolerate error) ([]byte, int, error) {
	var got []byte
	buf := make([]byte, 137)
	tolerated := 0
	for {
		n, err := r.Read(buf)
		got = append(got, buf[:n]...)
		switch {
		case err == nil:
		case tolerate != nil && err == tolerate:
			tolerated++
		default:
			return got, tolerated, err
		}
	}
}

func TestReaderReassemblesAnySplit(t *testing.T) {
	payloads := testPayloads(1, 300, 4096, 65535)
	want := bytes.Join(payloads, nil)
	for _, size := range []int{1, 7, 1448, 64 << 10, 1 << 20} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			conn := &scriptConn{steps: pieces(seal(testAEAD(t), payloads...), size)}
			got, _, err := readAll(newTestReader(t, conn), nil)
			if err != io.EOF || !bytes.Equal(got, want) {
				t.Fatalf("read %d bytes, %v", len(got), err)
			}
		})
	}
}

// Buffered ciphertext survives a timeout anywhere: the retry neither reopens a
// length chunk nor advances the nonce twice.
func TestReaderTimeoutResumesAnywhere(t *testing.T) {
	payloads := testPayloads(5, 40)
	wire := seal(testAEAD(t), payloads...)
	timeout := &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
	for cut := range len(wire) {
		conn := &scriptConn{steps: []step{{wire[:cut], timeout}, {data: wire[cut:]}}}
		got, timeouts, err := readAll(newTestReader(t, conn), timeout)
		if err != io.EOF || timeouts != 1 || !bytes.Equal(got, bytes.Join(payloads, nil)) {
			t.Fatalf("cut %d: %q, %d timeouts, %v", cut, got, timeouts, err)
		}
	}
}

func TestReaderTruncationIsSticky(t *testing.T) {
	payloads := testPayloads(5, 40)
	wire := seal(testAEAD(t), payloads...)
	frameEnd := 2 + 16 + 5 + 16
	for cut := range len(wire) + 1 {
		conn := &scriptConn{steps: []step{{data: wire[:cut]}}}
		r := newTestReader(t, conn)
		_, _, first := readAll(r, nil)
		reads := conn.reads
		_, second := r.Read(make([]byte, 1))
		if cut == 0 || cut == frameEnd || cut == len(wire) {
			if first != io.EOF || second != io.EOF || conn.reads == reads {
				t.Fatalf("boundary cut %d: %v, then %v", cut, first, second)
			}
			continue
		}
		if first != io.ErrUnexpectedEOF || second != first || conn.reads != reads {
			t.Fatalf("cut %d: %v, then %v after %d more reads", cut, first, second, conn.reads-reads)
		}
	}
}

func TestReaderEmptyReadsFail(t *testing.T) {
	conn := &scriptConn{steps: make([]step, 2*maxEmptyReads)}
	if _, err := newTestReader(t, conn).Read(make([]byte, 1)); err != io.ErrNoProgress || conn.reads != maxEmptyReads {
		t.Fatalf("Read = %v after %d reads", err, conn.reads)
	}
}

func TestReaderAuthenticationFailureIsSticky(t *testing.T) {
	payloads := testPayloads(5, 40)
	for _, offset := range []int{3, 2 + 16 + 5 + 16 + 20} {
		wire := seal(testAEAD(t), payloads...)
		wire[len(wire)-offset] ^= 1
		conn := &scriptConn{steps: []step{{data: wire}}}
		r := newTestReader(t, conn)
		got, _, err := readAll(r, nil)
		if !errors.Is(err, protocol.ErrFailAuth) || !bytes.Equal(got, payloads[0]) {
			t.Fatalf("offset %d: %q, %v", offset, got, err)
		}
		reads := conn.reads
		if _, again := r.Read(make([]byte, 1)); again != err || conn.reads != reads {
			t.Fatalf("authentication failure was not sticky: %v", again)
		}
	}
}

// An error returned with data waits until the data is used, as with bufio.
func TestReaderReportsErrorAfterItsData(t *testing.T) {
	payloads := testPayloads(5, 40)
	wire := seal(testAEAD(t), payloads...)
	conn := &scriptConn{steps: []step{{wire, io.EOF}}}
	got, _, err := readAll(newTestReader(t, conn), nil)
	if err != io.EOF || !bytes.Equal(got, bytes.Join(payloads, nil)) || conn.reads != 1 {
		t.Fatalf("read %q, %v after %d reads", got, err, conn.reads)
	}
}

func TestReaderBufferLifecycle(t *testing.T) {
	payloads := testPayloads(65535, 3)
	wire := seal(testAEAD(t), payloads...)
	frameEnd := 2 + 16 + 65535 + 16
	conn := &scriptConn{steps: []step{{data: wire[:frameEnd]}, {data: wire[frameEnd:]}}}
	r := newTestReader(t, conn)
	buf := make([]byte, 65535)
	if n, err := r.Read(buf[:10]); n != 10 || err != nil || len(r.buf) <= 65535 {
		t.Fatalf("Read = %d, %v with a %d-byte buffer", n, err, len(r.buf))
	}
	if _, err := io.ReadFull(r, buf[10:]); err != nil || !bytes.Equal(buf, payloads[0]) {
		t.Fatal(err)
	}
	if r.buf != nil {
		t.Fatalf("drained reader kept a %d-byte buffer", len(r.buf))
	}
	if n, err := r.Read(buf); n != 3 || err != nil || len(r.buf) != restSize {
		t.Fatalf("small frame = %d, %v with a %d-byte buffer", n, err, len(r.buf))
	}
	r.Close()
	if _, err := r.Read(buf); r.buf != nil || err != net.ErrClosed {
		t.Fatalf("Close kept the buffer or Read succeeded: %v", err)
	}
}

func TestReaderMaxChunksDoNotAllocate(t *testing.T) {
	const runs = 64
	payloads := make([][]byte, runs+1)
	for i := range payloads {
		payloads[i] = make([]byte, 65535)
	}
	conn := &scriptConn{steps: []step{{data: seal(testAEAD(t), payloads...)}}}
	r := newTestReader(t, conn)
	buf := make([]byte, 65535)
	if allocs := testing.AllocsPerRun(runs, func() {
		if _, err := io.ReadFull(r, buf); err != nil {
			t.Fatal(err)
		}
	}); allocs != 0 {
		t.Fatalf("%v allocations per chunk", allocs)
	}
}

// Seal must frame any split of a payload of small buffers as one contiguous
// payload would be.
func TestSealGathersBuffersIntoWholeChunks(t *testing.T) {
	aead := testAEAD(t)
	const maxChunk = 1000
	payload := make([]byte, 2*maxChunk+300)
	for i := range payload {
		payload[i] = byte(i)
	}
	var want []byte
	nonce := make([]byte, aead.NonceSize())
	for rest := payload; len(rest) > 0; {
		n := min(len(rest), maxChunk)
		want = aead.Seal(want, nonce, binary.BigEndian.AppendUint16(nil, uint16(n)), nil)
		common.BytesIncLittleEndian(nonce)
		want = aead.Seal(want, nonce, rest[:n], nil)
		common.BytesIncLittleEndian(nonce)
		rest = rest[n:]
	}
	for _, cuts := range [][]int{{}, {8}, {0, 8, 8, maxChunk}, {999, 1001, 1999, 2001}, {1, 2, 3, 2000}} {
		var v [][]byte
		last := 0
		for _, cut := range cuts {
			v = append(v, payload[last:cut])
			last = cut
		}
		v = append(v, payload[last:])
		nonce := make([]byte, aead.NonceSize())
		got := Seal([]byte("prefix"), aead, nonce, v, maxChunk)
		if !bytes.Equal(got, append([]byte("prefix"), want...)) {
			t.Fatalf("cuts %v: sealed stream differs", cuts)
		}
		if len(got) != len("prefix")+SealedSize(aead, v, maxChunk) {
			t.Fatalf("cuts %v: SealedSize disagrees with Seal", cuts)
		}
		if nonce[0] != 6 {
			t.Fatalf("cuts %v: nonce advanced %d times, want 6", cuts, nonce[0])
		}
	}
}

// Buffers of sealDirect bytes or more are sealed in chunks of their own, the
// small buffers between them gathered into shared chunks.
func TestSealKeepsLargeBuffersInTheirOwnChunks(t *testing.T) {
	aead := testAEAD(t)
	const maxChunk = 30000
	sizes := []int{100, sealDirect, 70000, 50, 0, 60, sealDirect + 1}
	chunks := []int{100, sealDirect, 30000, 30000, 10000, 110, sealDirect + 1}
	var v [][]byte
	var payload []byte
	for i, size := range sizes {
		b := bytes.Repeat([]byte{byte(i)}, size)
		v, payload = append(v, b), append(payload, b...)
	}
	var want []byte
	nonce := make([]byte, aead.NonceSize())
	for _, n := range chunks {
		want = aead.Seal(want, nonce, binary.BigEndian.AppendUint16(nil, uint16(n)), nil)
		common.BytesIncLittleEndian(nonce)
		want = aead.Seal(want, nonce, payload[:n], nil)
		common.BytesIncLittleEndian(nonce)
		payload = payload[n:]
	}
	nonce = make([]byte, aead.NonceSize())
	got := Seal(nil, aead, nonce, v, maxChunk)
	if !bytes.Equal(got, want) || len(got) != SealedSize(aead, v, maxChunk) {
		t.Fatalf("sealed %d bytes, SealedSize %d; want the %d bytes of chunks %v", len(got), SealedSize(aead, v, maxChunk), len(want), chunks)
	}
}
