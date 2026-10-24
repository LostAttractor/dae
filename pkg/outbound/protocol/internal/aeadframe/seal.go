package aeadframe

import (
	"crypto/cipher"
	"encoding/binary"

	"github.com/daeuniverse/dae/pkg/outbound/common"
)

// sealDirect is the smallest buffer sealed from itself in chunks of its own.
// Below it, copying the buffer into a chunk shared with its neighbours costs
// less than the extra chunk (AES-GCM and ChaCha20-Poly1305 on amd64).
const sealDirect = 16 << 10

// chunker walks the chunks Seal cuts the concatenation of v into: a buffer of
// at least sealDirect bytes is cut into chunks of its own, and smaller
// buffers are gathered into chunks that end before such a buffer.
type chunker struct {
	v        [][]byte
	maxChunk int
	i, off   int // the next byte is v[i][off]
}

// next returns the size of the next chunk, 0 at the end, and the chunk if it
// lies within one buffer, which it then consumes. gather consumes the others.
func (c *chunker) next() (int, []byte) {
	for c.i < len(c.v) && c.off == len(c.v[c.i]) {
		c.i, c.off = c.i+1, 0
	}
	if c.i == len(c.v) {
		return 0, nil
	}
	b := c.v[c.i][c.off:]
	n := len(b)
	if n < c.maxChunk && len(c.v[c.i]) < sealDirect {
		for j := c.i + 1; j < len(c.v) && n < c.maxChunk && len(c.v[j]) < sealDirect; j++ {
			n += min(len(c.v[j]), c.maxChunk-n)
		}
		if n > len(b) {
			return n, nil
		}
	}
	n = min(n, c.maxChunk)
	c.off += n
	return n, b[:n]
}

// gather appends the next n bytes to dst, or only consumes them if dst is nil.
func (c *chunker) gather(dst []byte, n int) []byte {
	for n > 0 {
		if c.off == len(c.v[c.i]) {
			c.i, c.off = c.i+1, 0
		}
		m := min(len(c.v[c.i])-c.off, n)
		if dst != nil {
			dst = append(dst, c.v[c.i][c.off:c.off+m]...)
		}
		c.off, n = c.off+m, n-m
	}
	return dst
}

// SealedSize is the wire size of v sealed by Seal.
func SealedSize(aead cipher.AEAD, v [][]byte, maxChunk int) int {
	size := 0
	c := chunker{v: v, maxChunk: maxChunk}
	for {
		n, whole := c.next()
		if n == 0 {
			return size
		}
		if whole == nil {
			c.gather(nil, n)
		}
		size += 2 + n + 2*aead.Overhead()
	}
}

// Seal appends the concatenation of v to dst in chunks of at most maxChunk
// bytes, advancing nonce once per sealed length and payload. A buffer of at
// least sealDirect bytes is sealed from itself in chunks of its own; smaller
// buffers are gathered into dst, as few chunks as fit between such buffers,
// and sealed in place. v is not modified. dst should have room for
// SealedSize more bytes.
func Seal(dst []byte, aead cipher.AEAD, nonce []byte, v [][]byte, maxChunk int) []byte {
	c := chunker{v: v, maxChunk: maxChunk}
	for {
		n, whole := c.next()
		if n == 0 {
			return dst
		}
		// Sealed in place: a length array passed to Seal would escape.
		start := len(dst)
		dst = binary.BigEndian.AppendUint16(dst, uint16(n))
		dst = aead.Seal(dst[:start], nonce, dst[start:], nil)
		common.BytesIncLittleEndian(nonce)
		if whole != nil {
			dst = aead.Seal(dst, nonce, whole, nil)
		} else {
			start = len(dst)
			dst = c.gather(dst, n)
			dst = aead.Seal(dst[:start], nonce, dst[start:], nil)
		}
		common.BytesIncLittleEndian(nonce)
	}
}
