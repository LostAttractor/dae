// SPDX-License-Identifier: AGPL-3.0-only

package membuffer

import (
	"io"
	"sync"
	"sync/atomic"
)

// View owns a reference to immutable bytes. Do not modify Bytes or use them
// after Close. Clone and Open hold independent references; callers close each
// owner explicitly. A View must not be copied or closed while using its bytes.
type View struct{ data *storage }

type storage struct {
	bytes  []byte
	refs   atomic.Int32
	budget *Budget
	memory Reservation
}

func newView(data []byte, memory Reservation, budget *Budget) *View {
	d := &storage{bytes: data, memory: memory, budget: budget}
	d.refs.Store(1)
	return &View{data: d}
}

func (d *storage) release() {
	if d.refs.Add(-1) == 0 {
		d.bytes = nil
		d.memory.Close()
	}
}

func (v *View) Bytes() []byte   { return v.data.bytes }
func (v *View) Budget() *Budget { return v.data.budget }
func (v *View) Clone() *View {
	v.data.refs.Add(1)
	return &View{data: v.data}
}

func (v *View) Close() {
	if v != nil && v.data != nil {
		v.data.release()
		v.data = nil
	}
}

func (v *View) Open() *Reader {
	v.data.refs.Add(1)
	return &Reader{data: v.data}
}

// Snapshot borrows an untouched reader's immutable storage, if available.
// It never reads input; nil means that the reader needs streaming or copying.
func Snapshot(r io.Reader) *View {
	if s, ok := r.(interface{ Snapshot() *View }); ok {
		return s.Snapshot()
	}
	return nil
}

// Reader is an independent cursor that releases its reference at EOF or Close.
// Read, Snapshot and Close may run concurrently. Each cursor advances and
// releases its reference independently of other cursors and views.
type Reader struct {
	mu     sync.Mutex
	data   *storage
	offset int
	closed bool
}

// Snapshot borrows an untouched cursor's storage without reading or copying.
// A nil result means the cursor has already consumed data or been closed.
func (r *Reader) Snapshot() *View {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.data == nil || r.offset != 0 {
		return nil
	}
	r.data.refs.Add(1)
	return &View{data: r.data}
}

func (r *Reader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, io.ErrClosedPipe
	}
	if r.data == nil {
		return 0, io.EOF
	}
	n := copy(p, r.data.bytes[r.offset:])
	r.offset += n
	if r.offset < len(r.data.bytes) {
		return n, nil
	}
	r.data.release()
	r.data = nil
	return n, io.EOF
}

func (r *Reader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	if r.data != nil {
		r.data.release()
		r.data = nil
	}
	return nil
}
