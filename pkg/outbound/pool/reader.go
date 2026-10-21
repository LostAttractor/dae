package pool

import (
	"bufio"
	"io"
	"sync"
)

// ReaderPool reuses buffered readers of a fixed size. It must not be copied.
type ReaderPool struct {
	pool sync.Pool
}

func NewReaderPool(size int) *ReaderPool {
	return &ReaderPool{pool: sync.Pool{
		New: func() any { return bufio.NewReaderSize(nil, size) },
	}}
}

func (p *ReaderPool) Get(r io.Reader) *bufio.Reader {
	reader := p.pool.Get().(*bufio.Reader)
	reader.Reset(r)
	return reader
}

// Put releases a reader obtained from this pool and detaches its source.
// The caller must finish all reads and use of buffered data before returning it.
func (p *ReaderPool) Put(reader *bufio.Reader) {
	reader.Reset(nil)
	p.pool.Put(reader)
}
