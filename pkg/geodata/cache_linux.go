// SPDX-License-Identifier: AGPL-3.0-only

package geodata

import (
	"encoding/binary"
	"errors"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// Drain kernel notifications synchronously before a cache lookup. A background
// watcher could lag behind a reload; timestamps alone miss same-tick rewrites.
type geodataWatcher struct{ fd int }

func newGeodataWatcher() (*geodataWatcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return nil, err
	}
	return &geodataWatcher{fd}, nil
}

func (w *geodataWatcher) add(f *os.File) (int, error) {
	// Follow the open inode even if its pathname is concurrently replaced.
	return unix.InotifyAddWatch(w.fd, "/proc/self/fd/"+strconv.Itoa(int(f.Fd())), unix.IN_MODIFY|unix.IN_ATTRIB|unix.IN_CLOSE_WRITE|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF)
}

func (w *geodataWatcher) remove(id int) { _, _ = unix.InotifyRmWatch(w.fd, uint32(id)) }
func (w *geodataWatcher) close()        { _ = unix.Close(w.fd) }

func (w *geodataWatcher) changes() (map[int]bool, bool, error) {
	var changed map[int]bool
	var overflow bool
	var buffer [4096]byte
	for {
		n, err := unix.Read(w.fd, buffer[:])
		if errors.Is(err, unix.EAGAIN) {
			return changed, overflow, nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, false, err
		}
		if n == 0 {
			return nil, false, os.ErrClosed
		}
		for offset := 0; offset+unix.SizeofInotifyEvent <= n; {
			event := buffer[offset:]
			id := int(int32(binary.NativeEndian.Uint32(event)))
			mask := binary.NativeEndian.Uint32(event[4:])
			length := int(binary.NativeEndian.Uint32(event[12:]))
			overflow = overflow || mask&unix.IN_Q_OVERFLOW != 0
			if changed == nil {
				changed = make(map[int]bool)
			}
			changed[id] = true
			offset += unix.SizeofInotifyEvent + length
		}
	}
}
