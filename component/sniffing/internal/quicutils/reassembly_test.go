/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package quicutils

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

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

func TestReassembleCryptosRejectsTruncatedData(t *testing.T) {
	_, err := ReassembleCryptos(nil, []byte{Quic_FrameType_Crypto, 0, 4, 'a', 'b'})
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
	if int(reassembly.dataSize) != MaxCryptoReassemblySize {
		t.Fatalf("Len() = %d, want %d", int(reassembly.dataSize), MaxCryptoReassemblySize)
	}
	if !reassembly.LimitExceeded() {
		t.Fatal("clipped CRYPTO data did not record the reassembly limit")
	}
	if reassembly.WindowComplete() {
		t.Fatal("sparse out-of-order data incorrectly completed the retained window")
	}
	if _, err := reassembly.Bytes(); !errors.Is(err, ErrMissingCrypto) {
		t.Fatalf("gap error = %v, want ErrMissingCrypto", err)
	}
	reassembly, err = ReassembleCryptos(reassembly, cryptoFrame(0, strings.Repeat("x", MaxCryptoReassemblySize-2)))
	if err != nil {
		t.Fatal(err)
	}
	got := reassembledBytes(t, reassembly)
	if got[MaxCryptoReassemblySize-2:] != "ab" {
		t.Fatalf("clipped tail = %q, want ab", got[MaxCryptoReassemblySize-2:])
	}

	reassembly, err = ReassembleCryptos(reassembly, cryptoFrame(1<<62-1, "ignored"))
	if err != nil {
		t.Fatalf("frame with an out-of-window offset: %v", err)
	}
	if after := reassembledBytes(t, reassembly); after != got {
		t.Fatalf("out-of-window frame changed retained data")
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
