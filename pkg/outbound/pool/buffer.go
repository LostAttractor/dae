// https://github.com/nadoo/glider/blob/main/pkg/pool/buffer.go

package pool

import (
	"math/bits"
	"sync"
	"unsafe"
)

const (
	// number of pools; the largest holds one 65535-byte AEAD chunk with its tag.
	num     = 18
	maxsize = 1 << (num - 1)
)

var (
	sizes [num]int
	pools [num]sync.Pool
)

func init() {
	for i := range num {
		size := 1 << i
		sizes[i] = size
		pools[i].New = func() any {
			buf := make([]byte, size)
			return unsafe.SliceData(buf)
		}
	}
}

// BufferCapacity returns the capacity GetBuffer(size) will allocate, so a
// caller can reserve memory before copying borrowed data into the pool.
func BufferCapacity(size int) int {
	if size >= 1 && size <= maxsize {
		return 1 << bits.Len(uint(size-1))
	}
	return size
}

// GetBuffer gets a buffer from pool, size should in range: [1, maxsize],
// otherwise, this function will call make([]byte, size) directly.
func GetBuffer(size int) []byte {
	if size >= 1 && size <= maxsize {
		i := bits.Len32(uint32(size - 1))
		if p := pools[i].Get().(*byte); p != nil {
			return unsafe.Slice(p, 1<<i)[:size]
		}
	}
	return make([]byte, size)
}

// PutBuffer puts a buffer into pool.
func PutBuffer(buf []byte) {
	if size := cap(buf); size >= 1 && size <= maxsize {
		i := bits.Len32(uint32(size - 1))
		if sizes[i] == size {
			pools[i].Put(unsafe.SliceData(buf))
		}
	}
}
