// SPDX-License-Identifier: AGPL-3.0-only

package geodata

import (
	"bufio"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"unicode"

	"google.golang.org/protobuf/encoding/protowire"
)

const geodataCacheBytes = 64 << 20

type indexedGeodata struct {
	info    os.FileInfo
	data    []byte
	entries map[string][]byte
	err     error
	weight  int
	watch   int
}

// Cache immutable file bytes and code offsets, never mutable protobuf objects.
// Identity is checked on the open descriptor so atomic file replacement and
// reload cannot mix an index with bytes from another version of the file.
var decodedFiles geodataFileCache

type geodataFileCache struct {
	sync.Mutex
	files   []*indexedGeodata // most recently used first; at most four files / 64 MiB
	watcher *geodataWatcher
}

func (c *geodataFileCache) decode(f *os.File, code string) ([]byte, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > geodataCacheBytes {
		return emitBytes(newBufferedSeeker(f), code)
	}
	c.Lock()
	defer c.Unlock()
	if c.watcher == nil {
		c.watcher, err = newGeodataWatcher()
		if err != nil {
			return emitBytes(newBufferedSeeker(f), code)
		}
	}
	changed, overflow, err := c.watcher.changes()
	if err != nil {
		c.watcher.close()
		c.watcher, c.files = nil, nil
		return emitBytes(newBufferedSeeker(f), code)
	}
	c.files = slices.DeleteFunc(c.files, func(file *indexedGeodata) bool {
		if overflow || changed[file.watch] {
			c.watcher.remove(file.watch)
			return true
		}
		return false
	})
	var indexed *indexedGeodata
	for i, file := range c.files {
		if os.SameFile(file.info, info) && file.info.Size() == info.Size() && file.info.ModTime() == info.ModTime() {
			indexed = file
			c.files = slices.Delete(c.files, i, i+1)
			break
		}
	}
	if indexed == nil {
		watch, err := c.watcher.add(f)
		if err != nil {
			return emitBytes(newBufferedSeeker(f), code)
		}
		keepWatch := false
		defer func() {
			if !keepWatch {
				c.watcher.remove(watch)
			}
		}()
		data, err := io.ReadAll(io.LimitReader(f, geodataCacheBytes+1))
		if err != nil {
			return nil, err
		}
		if len(data) > geodataCacheBytes {
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return nil, err
			}
			return emitBytes(newBufferedSeeker(f), code)
		}
		indexed = &indexedGeodata{info: info, data: data, watch: watch}
		indexed.entries, indexed.err = indexGeodata(data)
		indexed.weight = len(data)
		for key := range indexed.entries {
			indexed.weight += len(key) + 128 // include index allocation overhead
		}
		keepWatch = true
	}
	c.files = append([]*indexedGeodata{indexed}, c.files...)
	var size int
	for i, file := range c.files {
		size += file.weight
		if i >= 4 || size > geodataCacheBytes {
			for _, expired := range c.files[i:] {
				c.watcher.remove(expired.watch)
			}
			clear(c.files[i:])
			c.files = c.files[:i]
			break
		}
	}
	if indexed.err != nil {
		return nil, indexed.err
	}
	data, ok := indexed.entries[foldCode(code)]
	if !ok {
		return nil, errCodeNotFound
	}
	return slices.Clone(data), nil
}

func indexGeodata(data []byte) (map[string][]byte, error) {
	entries := make(map[string][]byte)
	for len(data) > 0 {
		if data[0] != 10 {
			return nil, errInvalidGeodataFile
		}
		entry, n := protowire.ConsumeBytes(data[1:])
		if n < 0 || len(entry) == 0 || entry[0] != 10 {
			return nil, errInvalidGeodataFile
		}
		code, ncode := protowire.ConsumeBytes(entry[1:])
		if ncode < 0 {
			return nil, errInvalidGeodataFile
		}
		key := foldCode(string(code))
		if _, exists := entries[key]; !exists {
			entries[key] = entry // preserve first-match behavior for duplicate codes
		}
		data = data[n+1:]
	}
	return entries, nil
}

// Use the same Unicode simple-fold equivalence as strings.EqualFold.
func foldCode(code string) string {
	return strings.Map(func(r rune) rune {
		for next := unicode.SimpleFold(r); ; next = unicode.SimpleFold(next) {
			if next <= r {
				return next
			}
		}
	}, code)
}

type bufferedSeeker struct {
	*bufio.Reader
	source io.ReadSeeker
}

func newBufferedSeeker(source io.ReadSeeker) *bufferedSeeker {
	return &bufferedSeeker{Reader: bufio.NewReader(source), source: source}
}

func (r *bufferedSeeker) Seek(offset int64, whence int) (int64, error) {
	if whence == io.SeekCurrent {
		offset -= int64(r.Buffered())
	}
	position, err := r.source.Seek(offset, whence)
	if err == nil {
		r.Reader.Reset(r.source)
	}
	return position, err
}
