// SPDX-License-Identifier: AGPL-3.0-only

package resource

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"
)

// The versioned index contains only bounded metadata and contiguous byte ranges.
// The digest covers the header, index and unencoded payload, not just the data.
var inputsMagic = [8]byte{'D', 'A', 'E', 'I', 'N', 'P', 0, 1}

const (
	inputsHeaderSize  = 28
	inputsFramingSize = inputsHeaderSize + sha256.Size
)

type inputIndexWriter struct{ bytes.Buffer }

func (w *inputIndexWriter) u8(n uint8) { w.WriteByte(n) }
func (w *inputIndexWriter) u32(n uint32) {
	w.Write(binary.LittleEndian.AppendUint32(nil, n))
}
func (w *inputIndexWriter) u64(n uint64) {
	w.Write(binary.LittleEndian.AppendUint64(nil, n))
}
func (w *inputIndexWriter) text(s string)           { w.u32(uint32(len(s))); w.WriteString(s) }
func (w *inputIndexWriter) diagnostic(e inputError) { w.u8(e.code); w.text(e.message) }

func boolByte(v bool) uint8 {
	if v {
		return 1
	}
	return 0
}

// Encode writes a complete recording. In-flight loads, earlier recording errors,
// cancellation and short writes are errors; no partial encoding is usable.
func (s *Inputs) Encode(w io.Writer) error {
	if s == nil {
		return fmt.Errorf("%w: no input recording", ErrInputRecording)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if s.pending != 0 {
		return fmt.Errorf("%w: input loads are still running", ErrInputRecording)
	}
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	entries := make([]*inputEntry, 0, len(s.entries))
	for _, e := range s.entries {
		entries = append(entries, e)
	}
	slices.SortFunc(entries, func(a, b *inputEntry) int {
		return cmp.Or(cmp.Compare(a.key.kind, b.key.kind), cmp.Compare(a.key.namespace, b.key.namespace), cmp.Compare(a.key.key, b.key.key))
	})
	var index inputIndexWriter
	var offset uint64
	for _, e := range entries {
		index.u8(e.key.kind)
		index.text(e.key.namespace)
		index.text(e.key.key)
		index.u64(uint64(e.maxBytes))
		index.diagnostic(e.err)
		index.diagnostic(e.refresh)
		index.diagnostic(e.write)
		index.u32(uint32(len(e.reads)))
		for _, r := range e.reads {
			index.text(r.source.Location)
			index.u8(boolByte(r.source.Relative))
			index.u64(uint64(r.maxBytes))
			index.text(r.userAgent)
			index.u8(boolByte(r.hasInterval))
			index.u64(uint64(r.interval))
			index.text(r.result.Location)
			index.diagnostic(r.err)
			index.u64(offset)
			index.u64(uint64(len(r.result.Data)))
			offset += uint64(len(r.result.Data))
		}
	}
	if int64(index.Len()) != s.indexBytes || offset != uint64(s.bytes) {
		return fmt.Errorf("%w: input accounting mismatch", ErrInputRecording)
	}
	header := append([]byte(nil), inputsMagic[:]...)
	header = binary.LittleEndian.AppendUint32(header, uint32(len(entries)))
	header = binary.LittleEndian.AppendUint32(header, uint32(s.reads))
	header = binary.LittleEndian.AppendUint32(header, uint32(index.Len()))
	header = binary.LittleEndian.AppendUint64(header, offset)
	digest := sha256.New()
	out := io.MultiWriter(w, digest)
	for _, part := range [][]byte{header, index.Bytes()} {
		if err := writeInputBytes(ctx, out, part); err != nil {
			return err
		}
	}
	for _, e := range entries {
		for _, r := range e.reads {
			if err := writeInputBytes(ctx, out, r.result.Data); err != nil {
				return err
			}
		}
	}
	return writeInputBytes(ctx, w, digest.Sum(nil))
}

func writeInputBytes(ctx context.Context, w io.Writer, data []byte) error {
	for len(data) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := min(len(data), 64<<10)
		written, err := w.Write(data[:n])
		if err != nil {
			return err
		}
		if written != n {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return ctx.Err()
}

type inputIndexReader struct {
	*bytes.Reader
	err error
}

func (r *inputIndexReader) number(n int) uint64 {
	var buf [8]byte
	if r.err == nil {
		_, r.err = io.ReadFull(r.Reader, buf[:n])
	}
	return binary.LittleEndian.Uint64(buf[:])
}
func (r *inputIndexReader) u8() uint8   { return uint8(r.number(1)) }
func (r *inputIndexReader) u32() uint32 { return uint32(r.number(4)) }
func (r *inputIndexReader) u64() uint64 { return r.number(8) }
func (r *inputIndexReader) boolean() bool {
	n := r.u8()
	if n > 1 {
		r.err = errors.New("invalid boolean")
	}
	return n == 1
}
func (r *inputIndexReader) text() string {
	n := r.u32()
	if n > maxInputString || uint64(n) > uint64(r.Len()) {
		r.err = errors.New("invalid string length")
	}
	if r.err != nil {
		return ""
	}
	buf := make([]byte, int(n))
	_, r.err = io.ReadFull(r.Reader, buf)
	return string(buf)
}
func (r *inputIndexReader) diagnostic() inputError {
	e := inputError{code: r.u8(), message: r.text()}
	if int(e.code) >= len(inputErrorCauses) || e.code == 0 && e.message != "" {
		r.err = errors.New("invalid input diagnostic")
	}
	return e
}

// DecodeInputs validates all lengths and counts before allocating payloads. It
// requires EOF after the checksum; callers should pass exactly the sealed input
// file, or a bounded reader for its region. It never opens referenced resources.
func DecodeInputs(r io.Reader) (_ *Inputs, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %w", ErrInputReplay, err)
		}
	}()
	digest := sha256.New()
	in := io.TeeReader(r, digest)
	var header [inputsHeaderSize]byte
	if _, err := io.ReadFull(in, header[:]); err != nil {
		return nil, err
	}
	if !bytes.Equal(header[:8], inputsMagic[:]) {
		return nil, errors.New("invalid input container version")
	}
	count := binary.LittleEndian.Uint32(header[8:])
	readCount := binary.LittleEndian.Uint32(header[12:])
	indexBytes := binary.LittleEndian.Uint32(header[16:])
	dataBytes := binary.LittleEndian.Uint64(header[20:])
	if count > maxInputKeys || readCount > maxInputReads || indexBytes > maxInputIndex || dataBytes > maxInputsBody || uint64(indexBytes)+dataBytes > maxInputsBody {
		return nil, errors.New("input container exceeds its byte, index or count limit")
	}
	index := make([]byte, int(indexBytes))
	if _, err := io.ReadFull(in, index); err != nil {
		return nil, err
	}
	idx := inputIndexReader{Reader: bytes.NewReader(index)}
	s := &Inputs{entries: make(map[inputKey]*inputEntry), bytes: int64(dataBytes), indexBytes: int64(indexBytes), reads: int(readCount)}
	entries := make([]*inputEntry, 0, int(count))
	lengths := make([]uint64, 0, int(readCount))
	var offset uint64
	var reads uint32
	for range count {
		e := &inputEntry{ready: make(chan struct{})}
		e.key = inputKey{kind: idx.u8(), namespace: idx.text(), key: idx.text()}
		e.maxBytes = int64(idx.u64())
		e.err, e.refresh, e.write = idx.diagnostic(), idx.diagnostic(), idx.diagnostic()
		n := idx.u32()
		if idx.err != nil {
			return nil, idx.err
		}
		if e.key.kind < inputBytes || e.key.kind > inputGroup || e.key.key == "" || e.maxBytes <= 0 || e.maxBytes > MaxInputBytes || n > maxGroupReads || n > readCount-reads {
			return nil, errors.New("invalid input entry identity, size or count")
		}
		if e.key.kind != inputGroup && (n != 1 || e.key.namespace != "" || e.refresh.code != 0 || e.write.code != 0) {
			return nil, errors.New("invalid single input entry")
		}
		if _, exists := s.entries[e.key]; exists {
			return nil, errors.New("duplicate input key")
		}
		s.entries[e.key] = e
		entries = append(entries, e)
		var total uint64
		for range n {
			record := inputReadRecord{}
			record.source = Source{Location: idx.text(), Relative: idx.boolean()}
			record.maxBytes = int64(idx.u64())
			record.userAgent = idx.text()
			record.hasInterval = idx.boolean()
			record.interval = time.Duration(idx.u64())
			record.result.Location = idx.text()
			record.err = idx.diagnostic()
			start, length := idx.u64(), idx.u64()
			if idx.err != nil {
				return nil, idx.err
			}
			limit := uint64(MaxInputBytes)
			if e.key.kind != inputGroup {
				limit = uint64(e.maxBytes)
			}
			if start != offset || length > limit-total || length > dataBytes-offset {
				return nil, errors.New("invalid input payload range")
			}
			if e.key.kind == inputBytes {
				if record.source != (Source{}) || record.maxBytes != 0 || record.userAgent != "" || record.hasInterval || record.interval != 0 || record.result.Location != "" || record.err.code != 0 {
					return nil, errors.New("invalid byte input metadata")
				}
			} else if !record.hasInterval && record.interval != 0 || record.err.code == 0 && (record.source.Location == "" || record.maxBytes <= 0 || length > uint64(record.maxBytes)) {
				return nil, errors.New("invalid resource read metadata")
			}
			// Validate the entire index before allocating any payload.
			lengths = append(lengths, length)
			e.reads = append(e.reads, record)
			total += length
			offset += length
			reads++
		}
	}
	if idx.err != nil || idx.Len() != 0 || offset != dataBytes || reads != readCount {
		return nil, errors.New("input index does not match the declared payload")
	}
	readIndex := 0
	for _, e := range entries {
		for i := range e.reads {
			e.reads[i].result.Data = make([]byte, int(lengths[readIndex]))
			readIndex++
			if _, err := io.ReadFull(in, e.reads[i].result.Data); err != nil {
				return nil, err
			}
		}
		close(e.ready)
	}
	var checksum [sha256.Size]byte
	if _, err := io.ReadFull(r, checksum[:]); err != nil {
		return nil, err
	}
	if !bytes.Equal(checksum[:], digest.Sum(nil)) {
		return nil, errors.New("input container checksum mismatch")
	}
	var trailing [1]byte
	if n, err := io.ReadFull(r, trailing[:]); n != 0 || !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("trailing input container data")
		}
		return nil, err
	}
	return s, nil
}
