/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package quicutils

import (
	"fmt"
	"io/fs"
	"sync"
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

type CryptoReassembler struct {
	data           [MaxCryptoReassemblySize]byte
	covered        [(MaxCryptoReassemblySize + 7) / 8]byte
	dataSize       uint16
	contiguousSize uint16
	limitExceeded  bool
}

var cryptoReassemblerPool sync.Pool

func acquireCryptoReassembler() *CryptoReassembler {
	if reassembly := cryptoReassemblerPool.Get(); reassembly != nil {
		return reassembly.(*CryptoReassembler)
	}
	return &CryptoReassembler{}
}

// ReleaseCryptoReassembler clears reassembly and transfers it to the pool.
func ReleaseCryptoReassembler(reassembly *CryptoReassembler) {
	if reassembly == nil {
		return
	}
	*reassembly = CryptoReassembler{}
	cryptoReassemblerPool.Put(reassembly)
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
		retained = acquireCryptoReassembler()
	}
	// The first pass validates the complete payload so an error cannot leave
	// retained state partially modified.
	_, _ = processCryptoFrames(retained, newPayload)
	return retained, nil
}

func processCryptoFrames(retained *CryptoReassembler, payload []byte) (hasData bool, err error) {
	for nextFrame := 0; nextFrame < len(payload); {
		appOffset, data, isCrypto, frameSize, limitExceeded, err := extractCryptoFrame(payload[nextFrame:])
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
	retainedEnd := int(r.dataSize)
	if offset >= retainedEnd {
		// Ordered, non-overlapping CRYPTO data can update storage and coverage in bulk.
		copy(r.data[offset:end], data)
		if offset < end {
			firstByte := offset >> 3
			lastByte := (end - 1) >> 3
			if firstByte == lastByte {
				width := end - offset
				r.covered[firstByte] |= byte(((1 << width) - 1) << (offset & 7))
			} else {
				r.covered[firstByte] |= byte(0xff << (offset & 7))
				for i := firstByte + 1; i < lastByte; i++ {
					r.covered[i] = 0xff
				}
				lastWidth := ((end - 1) & 7) + 1
				r.covered[lastByte] |= byte((1 << lastWidth) - 1)
			}
		}
		r.dataSize = uint16(end)
		if int(r.contiguousSize) == offset {
			r.contiguousSize = uint16(end)
		}
		return
	}
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

func extractCryptoFrame(remainder []byte) (appOffset int, data []byte, isCrypto bool, frameSize int, limitExceeded bool, err error) {
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
		for field := range 4 {
			value, err := readAckVarint()
			if err != nil {
				return 0, nil, false, 0, false, err
			}
			if field == 2 {
				ackRangeCount = value
			}
		}
		for range ackRangeCount {
			for range 2 {
				if _, err := readAckVarint(); err != nil {
					return 0, nil, false, 0, false, err
				}
			}
		}
		if frameType == Quic_FrameType_AckECN {
			for range 3 {
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
		if offset >= MaxCryptoReassemblySize {
			return 0, nil, true, frameSize, true, nil
		}
		if length > MaxCryptoReassemblySize-offset {
			dataLength = int(MaxCryptoReassemblySize - offset)
			limitExceeded = true
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

// Bytes exposes only contiguous retained CRYPTO data. Callers must not parse a
// ClientHello with missing fragments, even if later bytes contain its SNI/ALPN.
func (r *CryptoReassembler) Bytes() ([]byte, error) {
	if r == nil || r.contiguousSize != r.dataSize {
		return nil, ErrMissingCrypto
	}
	return r.data[:r.dataSize], nil
}

var ErrMissingCrypto = fmt.Errorf("missing crypto frame")
