/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package quicutils

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestLinearLocatorAcrossCryptoFrames(t *testing.T) {
	locator := NewLinearLocator([]*CryptoFrameOffset{
		{UpperAppOffset: 0, Data: []byte("abc")},
		{UpperAppOffset: 3, Data: []byte("defgh")},
	})

	got, err := locator.Range(1, 7)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("bcdefg")) {
		t.Fatalf("unexpected range: %q", got)
	}
}

func TestLinearLocatorSliceUsesExclusiveEnd(t *testing.T) {
	locator := NewLinearLocator([]*CryptoFrameOffset{
		{UpperAppOffset: 0, Data: []byte("abc")},
		{UpperAppOffset: 3, Data: []byte("defgh")},
	})

	sliced, err := locator.Slice(1, 7)
	if err != nil {
		t.Fatal(err)
	}
	if sliced.Len() != 6 {
		t.Fatalf("unexpected slice length: %d", sliced.Len())
	}
	got, err := sliced.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("bcdefg")) {
		t.Fatalf("unexpected slice: %q", got)
	}
}

func TestLinearLocatorRejectsMissingCrypto(t *testing.T) {
	locator := NewLinearLocator([]*CryptoFrameOffset{
		{UpperAppOffset: 0, Data: []byte("abc")},
		{UpperAppOffset: 4, Data: []byte("efgh")},
	})

	_, err := locator.Range(1, 7)
	if !errors.Is(err, ErrMissingCrypto) {
		t.Fatalf("expected ErrMissingCrypto, got %v", err)
	}
}

func TestLinearLocatorCanStartAfterMissingCrypto(t *testing.T) {
	frames := []*CryptoFrameOffset{
		{UpperAppOffset: 0, Data: []byte("abc")},
		{UpperAppOffset: 4, Data: []byte("ef")},
	}

	t.Run("range", func(t *testing.T) {
		got, err := NewLinearLocator(frames).Range(4, 6)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, []byte("ef")) {
			t.Fatalf("unexpected range: %q", got)
		}
	})
	t.Run("at", func(t *testing.T) {
		got, err := NewLinearLocator(frames).At(4)
		if err != nil {
			t.Fatal(err)
		}
		if got != 'e' {
			t.Fatalf("unexpected byte: %q", got)
		}
	})
	t.Run("slice", func(t *testing.T) {
		locator, err := NewLinearLocator(frames).Slice(4, 6)
		if err != nil {
			t.Fatal(err)
		}
		got, err := locator.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, []byte("ef")) {
			t.Fatalf("unexpected slice: %q", got)
		}
	})
}

func TestLinearLocatorAcceptsRetransmittedCrypto(t *testing.T) {
	locator := NewLinearLocator([]*CryptoFrameOffset{
		{UpperAppOffset: 0, Data: []byte("abc")},
		{UpperAppOffset: 0, Data: []byte("abc")},
		{UpperAppOffset: 3, Data: []byte("def")},
	})

	got, err := locator.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("abcdef")) {
		t.Fatalf("unexpected reassembled crypto: %q", got)
	}
}

func TestLinearLocatorAcceptsOverlappingCrypto(t *testing.T) {
	locator := NewLinearLocator([]*CryptoFrameOffset{
		{UpperAppOffset: 0, Data: []byte("abcd")},
		{UpperAppOffset: 2, Data: []byte("cdef")},
		{UpperAppOffset: 6, Data: []byte("gh")},
	})

	got, err := locator.Range(1, 8)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("bcdefgh")) {
		t.Fatalf("unexpected reassembled crypto: %q", got)
	}
}

func TestLinearLocatorContainedCryptoDoesNotShrinkLength(t *testing.T) {
	locator := NewLinearLocator([]*CryptoFrameOffset{
		{UpperAppOffset: 0, Data: []byte("abcdef")},
		{UpperAppOffset: 2, Data: []byte("cd")},
	})

	if locator.Len() != 6 {
		t.Fatalf("unexpected locator length: %d", locator.Len())
	}
	got, err := locator.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("abcdef")) {
		t.Fatalf("unexpected reassembled crypto: %q", got)
	}
}

func appendVarint(buf []byte, value uint64) []byte {
	var encoded [8]byte
	var length int
	switch {
	case value < 1<<6:
		encoded[0] = byte(value)
		length = 1
	case value < 1<<14:
		binary.BigEndian.PutUint16(encoded[:2], uint16(value)|0x4000)
		length = 2
	case value < 1<<30:
		binary.BigEndian.PutUint32(encoded[:4], uint32(value)|0x80000000)
		length = 4
	case value < 1<<62:
		binary.BigEndian.PutUint64(encoded[:], value|0xc000000000000000)
		length = 8
	default:
		panic("QUIC varint value out of range")
	}
	return append(buf, encoded[:length]...)
}

func cryptoFrame(offset uint64, data string) []byte {
	frame := appendVarint(nil, Quic_FrameType_Crypto)
	frame = appendVarint(frame, offset)
	frame = appendVarint(frame, uint64(len(data)))
	return append(frame, data...)
}

func reassembledBytes(t *testing.T, reassembly *CryptoReassembler) string {
	t.Helper()
	got, err := reassembly.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return string(got)
}

func TestReassembleCryptosHandlesRetransmissionsAndOverlaps(t *testing.T) {
	reassembly, err := ReassembleCryptos(nil, cryptoFrame(0, "abcd"))
	if err != nil {
		t.Fatal(err)
	}
	reassembly, err = ReassembleCryptos(reassembly, cryptoFrame(2, "XYef"))
	if err != nil {
		t.Fatal(err)
	}
	if got := reassembledBytes(t, reassembly); got != "abcdef" {
		t.Fatalf("reassembly = %q, want %q", got, "abcdef")
	}

	reassembly, err = ReassembleCryptos(reassembly, cryptoFrame(0, "XXXXXX"))
	if err != nil {
		t.Fatal(err)
	}
	if got := reassembledBytes(t, reassembly); got != "abcdef" {
		t.Fatalf("reassembly after retransmission = %q, want %q", got, "abcdef")
	}
}

func TestReassembleCryptosPreservesRetainedDataAcrossSpanningOverlap(t *testing.T) {
	reassembly, err := ReassembleCryptos(nil, append(cryptoFrame(0, "ab"), cryptoFrame(4, "ef")...))
	if err != nil {
		t.Fatal(err)
	}
	reassembly, err = ReassembleCryptos(reassembly, cryptoFrame(1, "bXYZZg"))
	if err != nil {
		t.Fatal(err)
	}
	if got := reassembledBytes(t, reassembly); got != "abXYefg" {
		t.Fatalf("reassembly = %q, want %q", got, "abXYefg")
	}
}

func TestReassembleCryptosHandlesOutOfOrderFrames(t *testing.T) {
	payload := append(cryptoFrame(4, "ef"), cryptoFrame(0, "abcd")...)
	reassembly, err := ReassembleCryptos(nil, payload)
	if err != nil {
		t.Fatal(err)
	}
	if got := reassembledBytes(t, reassembly); got != "abcdef" {
		t.Fatalf("reassembly = %q, want %q", got, "abcdef")
	}
}

func TestReassembleCryptosSkipsAckFrames(t *testing.T) {
	ack := []byte{Quic_FrameType_Ack, 4, 1, 1, 0, 0, 0}
	ackECN := []byte{Quic_FrameType_AckECN, 4, 1, 0, 0, 1, 2, 3}
	payload := append(append(ack, ackECN...), cryptoFrame(0, "hello")...)
	reassembly, err := ReassembleCryptos(nil, payload)
	if err != nil {
		t.Fatal(err)
	}
	if got := reassembledBytes(t, reassembly); got != "hello" {
		t.Fatalf("reassembly = %q, want hello", got)
	}
}

func TestReassembleCryptosRejectsTruncatedAckWithoutMutation(t *testing.T) {
	reassembly, err := ReassembleCryptos(nil, cryptoFrame(0, "hello"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReassembleCryptos(reassembly, []byte{Quic_FrameType_Ack, 1}); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("truncated ACK error = %v, want ErrOutOfRange", err)
	}
	if got := reassembledBytes(t, reassembly); got != "hello" {
		t.Fatalf("truncated ACK changed reassembly to %q", got)
	}
}

func TestExtractCryptoFrameOffsetRejectsTruncatedData(t *testing.T) {
	_, _, err := ExtractCryptoFrameOffset([]byte{Quic_FrameType_Crypto, 0, 4, 'a', 'b'}, 0)
	if !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("error = %v, want ErrOutOfRange", err)
	}
}

func TestExtractCryptoFrameOffsetRejectsIntOverflow(t *testing.T) {
	if strconv.IntSize != 32 {
		t.Skip("QUIC's 62-bit varint cannot overflow offset+length on a 64-bit int")
	}
	_, _, err := ExtractCryptoFrameOffset(cryptoFrame(1<<31-1, "x"), 0)
	if !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("error = %v, want ErrOutOfRange", err)
	}
}

func TestReassembleCryptosClipsAtClientHelloBoundary(t *testing.T) {
	payload := append(cryptoFrame(MaxCryptoReassemblySize, "ignored"), cryptoFrame(MaxCryptoReassemblySize-2, "abcd")...)
	reassembly, err := ReassembleCryptos(nil, payload)
	if err != nil {
		t.Fatal(err)
	}
	if reassembly.Len() != MaxCryptoReassemblySize {
		t.Fatalf("Len() = %d, want %d", reassembly.Len(), MaxCryptoReassemblySize)
	}
	if !reassembly.LimitExceeded() {
		t.Fatal("clipped CRYPTO data did not record the reassembly limit")
	}
	if reassembly.WindowComplete() {
		t.Fatal("sparse out-of-order data incorrectly completed the retained window")
	}
	got, err := reassembly.Range(MaxCryptoReassemblySize-2, MaxCryptoReassemblySize)
	if err != nil || string(got) != "ab" {
		t.Fatalf("clipped data = %q, %v; want %q", got, err, "ab")
	}
	if _, err := reassembly.Bytes(); !errors.Is(err, ErrMissingCrypto) {
		t.Fatalf("gap error = %v, want ErrMissingCrypto", err)
	}

	reassembly, err = ReassembleCryptos(reassembly, cryptoFrame(1<<62-1, "ignored"))
	if err != nil {
		t.Fatalf("frame with an out-of-window offset: %v", err)
	}
	got, err = reassembly.Range(MaxCryptoReassemblySize-2, MaxCryptoReassemblySize)
	if err != nil || string(got) != "ab" {
		t.Fatalf("out-of-window frame changed retained data: %q, %v", got, err)
	}
}

func TestReassembleCryptosRecordsWhollyOutOfWindowFrame(t *testing.T) {
	reassembly, err := ReassembleCryptos(nil, cryptoFrame(MaxCryptoReassemblySize, "ignored"))
	if err != nil {
		t.Fatal(err)
	}
	if reassembly == nil || !reassembly.LimitExceeded() {
		t.Fatal("out-of-window CRYPTO frame did not record the reassembly limit")
	}
	if reassembly.WindowComplete() {
		t.Fatal("out-of-window CRYPTO frame completed the retained window")
	}
}

func TestCryptoReassemblyWindowCompletesAfterGapFilled(t *testing.T) {
	reassembly, err := ReassembleCryptos(nil, cryptoFrame(MaxCryptoReassemblySize-2, "abcd"))
	if err != nil {
		t.Fatal(err)
	}
	if reassembly.WindowComplete() {
		t.Fatal("boundary-crossing frame completed a sparse window")
	}
	reassembly, err = ReassembleCryptos(reassembly, cryptoFrame(0, strings.Repeat("x", MaxCryptoReassemblySize-2)))
	if err != nil {
		t.Fatal(err)
	}
	if !reassembly.WindowComplete() {
		t.Fatal("contiguous retained window was not marked complete")
	}
}

func TestBuiltinBytesLocatorChecksBounds(t *testing.T) {
	locator := BuiltinBytesLocator("abc")
	if _, err := locator.Range(0, 4); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("Range error = %v, want ErrOutOfRange", err)
	}
	if _, err := locator.At(3); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("At error = %v, want ErrOutOfRange", err)
	}
	if _, err := locator.Slice(2, 1); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("Slice error = %v, want ErrOutOfRange", err)
	}
}

func TestReassembleCryptosHasBoundedStorageForThousandsOfTinyFrames(t *testing.T) {
	frames := make([][]byte, MaxCryptoReassemblySize)
	for i := range frames {
		frames[i] = cryptoFrame(uint64(i), "x")
	}

	var reassembly *CryptoReassembler
	allocations := testing.AllocsPerRun(5, func() {
		reassembly = nil
		for _, frame := range frames {
			var err error
			reassembly, err = ReassembleCryptos(reassembly, frame)
			if err != nil {
				panic(err)
			}
		}
	})
	if allocations > 2 {
		t.Fatalf("allocations = %.0f, want at most 2", allocations)
	}
	if len(reassembly.data) != MaxCryptoReassemblySize || len(reassembly.covered) != MaxCryptoReassemblySize/8 {
		t.Fatalf("unexpected retained capacity: data=%d coverage=%d", len(reassembly.data), len(reassembly.covered))
	}

	for _, frame := range frames {
		clear(frame)
	}
	got, err := reassembly.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range got {
		if b != 'x' {
			t.Fatalf("retained byte %d = %q, want %q", i, b, 'x')
		}
	}
}

func TestLinearLocatorRangeAcrossFrames(t *testing.T) {
	locator := NewLinearLocator([]*CryptoFrameOffset{
		{UpperAppOffset: 0, Data: []byte("ab")},
		{UpperAppOffset: 2, Data: []byte("cd")},
	})
	got, err := locator.Range(1, 4)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "bcd" {
		t.Fatalf("Range() = %q, want %q", got, "bcd")
	}
}

func TestLinearLocatorRejectsMissingAndOutOfRangeData(t *testing.T) {
	locator := NewLinearLocator([]*CryptoFrameOffset{
		{UpperAppOffset: 0, Data: []byte("ab")},
		{UpperAppOffset: 3, Data: []byte("cd")},
	})
	if _, err := locator.Range(0, 5); !errors.Is(err, ErrMissingCrypto) {
		t.Fatalf("gap error = %v, want ErrMissingCrypto", err)
	}

	for _, bounds := range [][2]int{{-1, 0}, {2, 1}, {0, 6}} {
		locator = NewLinearLocator([]*CryptoFrameOffset{{UpperAppOffset: 0, Data: []byte("abcde")}})
		if _, err := locator.Range(bounds[0], bounds[1]); !errors.Is(err, ErrOutOfRange) {
			t.Fatalf("Range(%d, %d) error = %v, want ErrOutOfRange", bounds[0], bounds[1], err)
		}
	}
}

func TestLinearLocatorSliceUsesHalfOpenBounds(t *testing.T) {
	locator := NewLinearLocator([]*CryptoFrameOffset{{UpperAppOffset: 0, Data: []byte("abcde")}})
	slice, err := locator.Slice(1, 4)
	if err != nil {
		t.Fatal(err)
	}
	if slice.Len() != 3 {
		t.Fatalf("Len() = %d, want 3", slice.Len())
	}
	got, err := slice.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "bcd" {
		t.Fatalf("Bytes() = %q, want %q", got, "bcd")
	}
	if _, err := locator.At(locator.Len()); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("At(Len()) error = %v, want ErrOutOfRange", err)
	}
}
