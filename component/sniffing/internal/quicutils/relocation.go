/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package quicutils

import (
	"fmt"
	"io/fs"
)

var (
	ErrUnknownFrameType = fmt.Errorf("unknown frame type")
	ErrOutOfRange       = fmt.Errorf("index out of range")
)

const (
	Quic_FrameType_Padding          = 0
	Quic_FrameType_Ping             = 1
	Quic_FrameType_Ack              = 2
	Quic_FrameType_AckECN           = 3
	Quic_FrameType_Crypto           = 6
	Quic_FrameType_ConnectionClose  = 0x1c
	Quic_FrameType_ConnectionClose2 = 0x1d

	// MaxCryptoReassemblySize bounds data retained for QUIC SNI sniffing. It
	// matches the existing 4 KiB ClientHello budget of this best-effort sniffer.
	MaxCryptoReassemblySize = 4096
)

type CryptoFrameOffset struct {
	UpperAppOffset int
	// Offset of data in quic payload.
	Data []byte
}

type CryptoReassembler struct {
	data           [MaxCryptoReassemblySize]byte
	covered        [(MaxCryptoReassemblySize + 7) / 8]byte
	dataSize       uint16
	contiguousSize uint16
	limitExceeded  bool
}

func ReassembleCryptos(retained *CryptoReassembler, newPayload []byte) (*CryptoReassembler, error) {
	hasData, err := processCryptoFrames(nil, newPayload)
	if err != nil {
		return nil, err
	}
	if !hasData {
		return retained, nil
	}
	if retained == nil {
		retained = &CryptoReassembler{}
	}
	// The first pass validates the complete payload so an error cannot leave
	// retained state partially modified.
	_, _ = processCryptoFrames(retained, newPayload)
	return retained, nil
}

func processCryptoFrames(retained *CryptoReassembler, payload []byte) (hasData bool, err error) {
	for nextFrame := 0; nextFrame < len(payload); {
		appOffset, data, isCrypto, frameSize, limitExceeded, err := extractCryptoFrame(payload[nextFrame:], MaxCryptoReassemblySize)
		if err != nil {
			return false, err
		}
		nextFrame += frameSize
		if retained != nil && limitExceeded {
			retained.limitExceeded = true
		}
		if !isCrypto {
			continue
		}
		hasData = true
		if retained != nil && len(data) != 0 {
			retained.retain(appOffset, data)
		}
	}
	return hasData, nil
}

func (r *CryptoReassembler) retain(offset int, data []byte) {
	end := offset + len(data)
	if end > int(r.dataSize) {
		r.dataSize = uint16(end)
	}
	for i, b := range data {
		position := offset + i
		mask := byte(1 << (position & 7))
		coverage := &r.covered[position>>3]
		if *coverage&mask != 0 {
			continue
		}
		r.data[position] = b
		*coverage |= mask
	}
	for int(r.contiguousSize) < int(r.dataSize) {
		position := int(r.contiguousSize)
		if r.covered[position>>3]&(1<<(position&7)) == 0 {
			break
		}
		r.contiguousSize++
	}
}

func (r *CryptoReassembler) WindowComplete() bool {
	return r != nil && r.contiguousSize == MaxCryptoReassemblySize
}

func ExtractCryptoFrameOffset(remainder []byte, transportOffset int) (offset *CryptoFrameOffset, frameSize int, err error) {
	appOffset, data, isCrypto, frameSize, _, err := extractCryptoFrame(remainder, 0)
	if err != nil || !isCrypto {
		return nil, frameSize, err
	}
	return &CryptoFrameOffset{UpperAppOffset: appOffset, Data: data}, frameSize, nil
}

func extractCryptoFrame(remainder []byte, cryptoLimit uint64) (appOffset int, data []byte, isCrypto bool, frameSize int, limitExceeded bool, err error) {
	if len(remainder) == 0 {
		return 0, nil, false, 0, false, fmt.Errorf("frame has no length: %w", ErrOutOfRange)
	}
	frameType, nextField, err := BigEndianUvarint(remainder)
	if err != nil {
		return 0, nil, false, 0, false, err
	}
	switch frameType {
	case Quic_FrameType_Ping:
		return 0, nil, false, nextField, false, nil
	case Quic_FrameType_Padding:
		for ; nextField < len(remainder) && remainder[nextField] == 0; nextField++ {
		}
		return 0, nil, false, nextField, false, nil
	case Quic_FrameType_Ack, Quic_FrameType_AckECN:
		readAckVarint := func() (uint64, error) {
			value, n, err := BigEndianUvarint(remainder[nextField:])
			if err != nil {
				return 0, fmt.Errorf("ACK frame field is truncated: %v: %w", err, ErrOutOfRange)
			}
			nextField += n
			return value, nil
		}
		var ackRangeCount uint64
		for field := 0; field < 4; field++ {
			value, err := readAckVarint()
			if err != nil {
				return 0, nil, false, 0, false, err
			}
			if field == 2 {
				ackRangeCount = value
			}
		}
		for rangeIndex := uint64(0); rangeIndex < ackRangeCount; rangeIndex++ {
			for rangeField := 0; rangeField < 2; rangeField++ {
				if _, err := readAckVarint(); err != nil {
					return 0, nil, false, 0, false, err
				}
			}
		}
		if frameType == Quic_FrameType_AckECN {
			for ecnCounter := 0; ecnCounter < 3; ecnCounter++ {
				if _, err := readAckVarint(); err != nil {
					return 0, nil, false, 0, false, err
				}
			}
		}
		return 0, nil, false, nextField, false, nil
	case Quic_FrameType_Crypto:
		offset, n, err := BigEndianUvarint(remainder[nextField:])
		if err != nil {
			return 0, nil, false, 0, false, err
		}
		nextField += n

		length, n, err := BigEndianUvarint(remainder[nextField:])
		if err != nil {
			return 0, nil, false, 0, false, err
		}
		nextField += n
		if length > uint64(len(remainder)-nextField) {
			return 0, nil, false, 0, false, fmt.Errorf("crypto frame data out of range: %w", ErrOutOfRange)
		}
		dataLength := int(length)
		frameSize = nextField + dataLength
		if cryptoLimit != 0 {
			if offset >= cryptoLimit {
				return 0, nil, true, frameSize, true, nil
			}
			if length > cryptoLimit-offset {
				dataLength = int(cryptoLimit - offset)
				limitExceeded = true
			}
		} else {
			maxInt := uint64(^uint(0) >> 1)
			if offset > maxInt || length > maxInt-offset {
				return 0, nil, false, 0, false, fmt.Errorf("crypto frame range out of range: %w", ErrOutOfRange)
			}
		}

		return int(offset), remainder[nextField : nextField+dataLength], true, frameSize, limitExceeded, nil
	case Quic_FrameType_ConnectionClose, Quic_FrameType_ConnectionClose2:
		return 0, nil, false, 0, false, fmt.Errorf("connection closed: %w", fs.ErrClosed)
	default:
		return 0, nil, false, 0, false, fmt.Errorf("%w: %v", ErrUnknownFrameType, frameType)
	}
}

func (r *CryptoReassembler) LimitExceeded() bool {
	return r != nil && r.limitExceeded
}

func (r *CryptoReassembler) Range(i, j int) ([]byte, error) {
	return cryptoRange(r, 0, r.Len(), i, j)
}

func (r *CryptoReassembler) At(i int) (byte, error) {
	b, err := r.Range(i, i+1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *CryptoReassembler) Slice(i, j int) (Locator, error) {
	if i < 0 || j < i || j > r.Len() {
		return nil, ErrOutOfRange
	}
	return &cryptoReassemblyView{reassembler: r, left: i, length: j - i}, nil
}

func (r *CryptoReassembler) Bytes() ([]byte, error) {
	return r.Range(0, r.Len())
}

func (r *CryptoReassembler) Len() int {
	if r == nil {
		return 0
	}
	return int(r.dataSize)
}

type cryptoReassemblyView struct {
	reassembler *CryptoReassembler
	left        int
	length      int
}

func (v *cryptoReassemblyView) Range(i, j int) ([]byte, error) {
	return cryptoRange(v.reassembler, v.left, v.length, i, j)
}

func (v *cryptoReassemblyView) At(i int) (byte, error) {
	b, err := v.Range(i, i+1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (v *cryptoReassemblyView) Slice(i, j int) (Locator, error) {
	if i < 0 || j < i || j > v.length {
		return nil, ErrOutOfRange
	}
	return &cryptoReassemblyView{reassembler: v.reassembler, left: v.left + i, length: j - i}, nil
}

func (v *cryptoReassemblyView) Bytes() ([]byte, error) {
	return v.Range(0, v.length)
}

func (v *cryptoReassemblyView) Len() int {
	return v.length
}

func cryptoRange(r *CryptoReassembler, left, length, i, j int) ([]byte, error) {
	if i < 0 || j < i || j > length {
		return nil, ErrOutOfRange
	}
	if i == j {
		return []byte{}, nil
	}
	if r == nil {
		return nil, ErrMissingCrypto
	}
	i += left
	j += left
	for position := i; position < j; position++ {
		if r.covered[position>>3]&(1<<(position&7)) == 0 {
			return nil, ErrMissingCrypto
		}
	}
	return r.data[i:j], nil
}

var (
	ErrMissingCrypto = fmt.Errorf("missing crypto frame")
)

type Locator interface {
	Range(i, j int) ([]byte, error)
	Slice(i, j int) (Locator, error)
	At(i int) (byte, error)
	Len() int
	Bytes() ([]byte, error)
}

var _ Locator = &CryptoReassembler{}
var _ Locator = &cryptoReassemblyView{}

// LinearLocator only searches forward.
type LinearLocator struct {
	left      int
	length    int
	iOuter    int
	baseEnd   int
	baseStart int
	baseData  []byte
	o         []*CryptoFrameOffset
}

func NewLinearLocator(o []*CryptoFrameOffset) *LinearLocator {
	if len(o) == 0 {
		return &LinearLocator{}
	}
	length := 0
	for _, frame := range o {
		if end := frame.UpperAppOffset + len(frame.Data); end > length {
			length = end
		}
	}
	return &LinearLocator{
		left:      0,
		length:    length,
		iOuter:    0,
		baseData:  o[0].Data,
		baseStart: o[0].UpperAppOffset,
		baseEnd:   o[0].UpperAppOffset + len(o[0].Data),
		o:         o,
	}
}

func (l *LinearLocator) advance() (contiguous bool, err error) {
	previousEnd := l.baseEnd
	for l.iOuter+1 < len(l.o) {
		next := l.o[l.iOuter+1]
		nextStart := next.UpperAppOffset
		nextEnd := nextStart + len(next.Data)
		l.iOuter++
		if nextEnd <= l.baseEnd {
			continue
		}
		l.baseData = next.Data
		l.baseStart = nextStart
		l.baseEnd = nextEnd
		return nextStart <= previousEnd, nil
	}
	return false, ErrMissingCrypto
}

func (l *LinearLocator) relocate(i int) error {
	// Relocate ll.iOuter.
	for i >= l.baseEnd {
		if _, err := l.advance(); err != nil {
			return err
		}
	}
	if i < l.baseStart {
		return ErrMissingCrypto
	}
	return nil
}

func (l *LinearLocator) Range(i, j int) ([]byte, error) {
	if i < 0 || j < i || j > l.length {
		return nil, ErrOutOfRange
	}
	if i == j {
		return []byte{}, nil
	}
	if len(l.o) == 0 {
		return nil, ErrMissingCrypto
	}
	size := j - i

	// We find bytes including i and j, so we should sub j with 1.
	i += l.left
	j += l.left - 1
	if err := l.relocate(i); err != nil {
		return nil, err
	}

	// Linearly copy.

	if j < l.baseEnd {
		// In the same block, no copy needed.
		return l.baseData[i-l.baseStart : j-l.baseStart+1], nil
	}

	b := make([]byte, size)
	k := 0
	for j >= l.baseEnd {
		n := copy(b[k:], l.baseData[i-l.baseStart:])
		k += n
		i += n
		contiguous, err := l.advance()
		if err != nil {
			return nil, err
		}
		if !contiguous {
			return nil, ErrMissingCrypto
		}
	}
	copy(b[k:], l.baseData[i-l.baseStart:j-l.baseStart+1])
	return b, nil
}

func (l *LinearLocator) At(i int) (byte, error) {
	if i < 0 || i >= l.length {
		return 0, ErrOutOfRange
	}
	if len(l.o) == 0 {
		return 0, ErrMissingCrypto
	}
	i += l.left

	if err := l.relocate(i); err != nil {
		return 0, err
	}
	b := l.baseData[i-l.baseStart]
	return b, nil
}

func (l *LinearLocator) Slice(i, j int) (Locator, error) {
	if i < 0 || j < i || j > l.length {
		return nil, ErrOutOfRange
	}
	newLL := *l
	newLL.left += i
	newLL.length = j - i
	return &newLL, nil
}

func (l *LinearLocator) Bytes() ([]byte, error) {
	return l.Range(0, l.length)
}

var _ Locator = &LinearLocator{}

func (l *LinearLocator) Len() int {
	return l.length
}

type BuiltinBytesLocator []byte

func (l BuiltinBytesLocator) Range(i, j int) ([]byte, error) {
	if i < 0 || j < i || j > len(l) {
		return nil, ErrOutOfRange
	}
	return l[i:j], nil
}
func (l BuiltinBytesLocator) At(i int) (byte, error) {
	if i < 0 || i >= len(l) {
		return 0, ErrOutOfRange
	}
	return l[i], nil
}
func (l BuiltinBytesLocator) Slice(i, j int) (Locator, error) {
	if i < 0 || j < i || j > len(l) {
		return nil, ErrOutOfRange
	}
	return l[i:j], nil
}
func (l BuiltinBytesLocator) Len() int {
	return len(l)
}
func (l BuiltinBytesLocator) Bytes() ([]byte, error) {
	return l, nil
}

var _ Locator = BuiltinBytesLocator{}
