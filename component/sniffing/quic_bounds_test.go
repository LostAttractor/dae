/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"bytes"
	"errors"
	"testing"
)

func TestParseQuicInitialHeader(t *testing.T) {
	packet := []byte{
		0xc0, 0, 0, 0, 1, // v1 Initial
		2, 0xaa, 0xbb, // destination connection ID
		1, 0xcc, // source connection ID
		0, // token length
		4, // packet length
		1, 2, 3, 4,
		0xff, // next coalesced packet
	}
	destConnId, headerEnd, packetEnd, ok := parseQuicInitialHeader(packet)
	if !ok {
		t.Fatal("valid Initial header was rejected")
	}
	if !bytes.Equal(destConnId, []byte{0xaa, 0xbb}) {
		t.Fatalf("destination connection ID = %x", destConnId)
	}
	if headerEnd != 16 || packetEnd != 16 {
		t.Fatalf("header end = %d, packet end = %d; want 16, 16", headerEnd, packetEnd)
	}
}

func TestSniffQuicBlockRejectsOversizedVarintLengths(t *testing.T) {
	header := []byte{0xc0, 0, 0, 0, 1, 0, 0}
	maxVarint := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	tests := []struct {
		name string
		buf  []byte
	}{
		{name: "token", buf: append(append([]byte{}, header...), maxVarint...)},
		{name: "packet", buf: append(append(append([]byte{}, header...), 0), maxVarint...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := sniffQuicBlock(nil, tt.buf)
			if !errors.Is(err, ErrNotApplicable) {
				t.Fatalf("error = %v, want ErrNotApplicable", err)
			}
		})
	}
}
