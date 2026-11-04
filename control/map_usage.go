// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Read the kernel's existing counters, not map values or packet-path counters.
// A reader belongs to one generation and is loaded only when status needs it.
type kernelTableReader struct {
	mu       sync.Mutex
	objects  *bpfusageObjects
	iterator *link.Iter
	ids      map[*ebpf.Map]ebpf.MapID
	closed   bool
}

func (r *kernelTableReader) mapID(m *ebpf.Map, cache bool) (ebpf.MapID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || m.FD() < 0 {
		return 0, net.ErrClosed
	}
	if id := r.ids[m]; id != 0 {
		return id, nil
	}
	info, err := m.Info()
	if err != nil {
		return 0, err
	}
	id, ok := info.ID()
	if !ok {
		return 0, errors.New("kernel map ID unavailable")
	}
	// Cache only maps held for this generation, not borrowed inner-map FDs.
	if cache {
		if r.ids == nil {
			r.ids = make(map[*ebpf.Map]ebpf.MapID)
		}
		r.ids[m] = id
	}
	return id, nil
}

func (r *kernelTableReader) read(ids []ebpf.MapID) (map[ebpf.MapID]int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, net.ErrClosed
	}
	if r.objects == nil {
		objects := new(bpfusageObjects)
		if err := loadBpfusageObjects(objects, &ebpf.CollectionOptions{Cache: kernelBTFCache}); err != nil {
			return nil, err
		}
		r.objects = objects
	}
	requested := make([]uint32, r.objects.RequestedMapIds.Size()/4)
	if len(ids) > len(requested) {
		return nil, fmt.Errorf("too many kernel tables: %d > %d", len(ids), len(requested))
	}
	for i, id := range ids {
		requested[i] = uint32(id)
	}
	if err := r.objects.RequestedMapIds.Set(requested); err != nil {
		return nil, err
	}
	if r.iterator == nil {
		iterator, err := link.AttachIter(link.IterOptions{Program: r.objects.ReadMapUsage})
		if err != nil {
			return nil, err
		}
		r.iterator = iterator
	}
	stream, err := r.iterator.Open()
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	entrySize := binary.Size(bpfusageMapUsage{})
	data, err := io.ReadAll(io.LimitReader(stream, int64(len(ids)*entrySize+1)))
	if err != nil {
		return nil, err
	}
	if len(data)%entrySize != 0 || len(data) > len(ids)*entrySize {
		return nil, errors.New("invalid kernel table counter response")
	}
	entries := make([]bpfusageMapUsage, len(data)/entrySize)
	if _, err := binary.Decode(data, binary.NativeEndian, entries); err != nil {
		return nil, err
	}
	counts := make(map[ebpf.MapID]int, len(entries))
	for _, entry := range entries {
		// Per-CPU counters are not an atomic snapshot during concurrent churn.
		counts[ebpf.MapID(entry.Id)] = int(max(0, min(entry.Used, int64(entry.Limit))))
	}
	return counts, nil
}

func (r *kernelTableReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	r.ids = nil
	var err error
	if r.iterator != nil {
		err = r.iterator.Close()
	}
	if r.objects != nil {
		err = errors.Join(err, r.objects.Close())
	}
	return err
}
