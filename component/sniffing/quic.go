/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"encoding/binary"
	"errors"
	"io/fs"

	"github.com/daeuniverse/dae/component/sniffing/internal/quicutils"
	"github.com/daeuniverse/outbound/pool"
)

const (
	QuicFlag_PacketNumberLength = iota
	QuicFlag_PacketNumberLength1
	QuicFlag_Reserved
	QuicFlag_Reserved1
	QuicFlag_LongPacketType
	QuicFlag_LongPacketType1
	QuicFlag_FixedBit
	QuicFlag_HeaderForm
)
const (
	QuicFlag_HeaderForm_LongHeader    = 1
	QuicFlag_LongPacketType_InitialV1 = 0
	QuicFlag_LongPacketType_InitialV2 = 1
)

func (s *Sniffer) SniffQuic() (d string, err error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	return s.sniffQuicLocked()
}

// sniffQuicLocked requires s.readMu to be held.
func (s *Sniffer) sniffQuicLocked() (d string, err error) {
	remaining := s.buf.Bytes()[s.quicNextRead:]
	parsedInitial := false
	for {
		s.quicCryptos, remaining, err = sniffQuicBlock(s.quicCryptos, remaining)
		if err == nil {
			parsedInitial = true
			if len(remaining) == 0 {
				break
			}
			continue
		}
		if errors.Is(err, ErrNotApplicable) && parsedInitial {
			// Ignore an unexpected trailing block after a valid Initial.
			break
		}
		if errors.Is(err, fs.ErrClosed) {
			return "", ErrNotFound
		}
		return "", err
	}

	s.quicNextRead = s.buf.Len()
	sni, err := extractSniFromTls(s.quicCryptos)
	if err != nil {
		if !s.quicCryptos.WindowComplete() {
			s.needMore = true
		}
		return "", ErrNotFound
	}
	return sni, nil
}

// parseQuicInitialHeader parses the unprotected portion of a QUIC Initial.
func parseQuicInitialHeader(buf []byte) (destConnId []byte, headerEnd, packetEnd int, ok bool) {
	const dstConnIdPos = 6
	if len(buf) < dstConnIdPos {
		return nil, 0, 0, false
	}

	protectedFlag := buf[0]
	if ((protectedFlag >> QuicFlag_HeaderForm) & 0b11) != QuicFlag_HeaderForm_LongHeader {
		return nil, 0, 0, false
	}
	version, err := quicutils.ParseVersion(binary.BigEndian.Uint32(buf[1:5]))
	if err != nil {
		return nil, 0, 0, false
	}
	initialType := byte(QuicFlag_LongPacketType_InitialV1)
	if version == quicutils.Version_V2 {
		initialType = QuicFlag_LongPacketType_InitialV2
	}
	if ((protectedFlag >> QuicFlag_LongPacketType) & 0b11) != initialType {
		return nil, 0, 0, false
	}

	cursor := dstConnIdPos
	destConnIdLength := int(buf[cursor-1])
	if destConnIdLength > len(buf)-cursor {
		return nil, 0, 0, false
	}
	destConnId = buf[cursor : cursor+destConnIdLength]
	cursor += destConnIdLength

	if cursor >= len(buf) {
		return nil, 0, 0, false
	}
	srcConnIdLength := int(buf[cursor])
	cursor++
	if srcConnIdLength > len(buf)-cursor {
		return nil, 0, 0, false
	}
	cursor += srcConnIdLength

	tokenLength, n, err := quicutils.BigEndianUvarint(buf[cursor:])
	if err != nil {
		return nil, 0, 0, false
	}
	cursor += n
	if tokenLength > uint64(len(buf)-cursor) {
		return nil, 0, 0, false
	}
	cursor += int(tokenLength)

	length, n, err := quicutils.BigEndianUvarint(buf[cursor:])
	if err != nil {
		return nil, 0, 0, false
	}
	cursor += n
	if length > uint64(len(buf)-cursor) || length < quicutils.MaxPacketNumberLength {
		return nil, 0, 0, false
	}
	packetEnd = cursor + int(length)
	headerEnd = cursor + quicutils.MaxPacketNumberLength
	return destConnId, headerEnd, packetEnd, true
}

func sniffQuicBlock(cryptos *quicutils.CryptoReassembler, buf []byte) (new *quicutils.CryptoReassembler, next []byte, err error) {
	destConnId, headerEnd, packetEnd, ok := parseQuicInitialHeader(buf)
	if !ok {
		return cryptos, nil, ErrNotApplicable
	}

	header := buf[:headerEnd]
	originalFirstByte := header[0]
	var originalPacketNumber [quicutils.MaxPacketNumberLength]byte
	copy(originalPacketNumber[:], header[headerEnd-quicutils.MaxPacketNumberLength:])
	defer func() {
		header[0] = originalFirstByte
		copy(header[headerEnd-quicutils.MaxPacketNumberLength:], originalPacketNumber[:])
	}()

	plaintextBuffer := pool.GetBuffer(packetEnd - headerEnd)
	defer pool.PutBuffer(plaintextBuffer)
	plaintext, err := quicutils.DecryptQuic_(plaintextBuffer[:0], header, packetEnd, destConnId)
	if err != nil {
		return cryptos, nil, ErrNotApplicable
	}
	// Reassembly copies retained CRYPTO bytes before plaintextBuffer is returned.
	if new, err = quicutils.ReassembleCryptos(cryptos, plaintext); err != nil {
		if errors.Is(err, fs.ErrClosed) {
			return cryptos, nil, err
		}
		return cryptos, buf[packetEnd:], ErrNotApplicable
	}
	return new, buf[packetEnd:], nil
}
