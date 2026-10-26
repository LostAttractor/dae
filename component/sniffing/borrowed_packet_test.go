// SPDX-License-Identifier: AGPL-3.0-only

package sniffing

import (
	"bytes"
	"errors"
	"testing"
)

func TestBorrowedQUICPacketsKeepReplayBytes(t *testing.T) {
	s := NewPacketSniffer(nil)
	defer s.Close()
	for i, original := range [][]byte{QuicStream2_1, QuicStream2_2} {
		packet := bytes.Clone(original)
		s.AppendBorrowedData(packet)
		if &s.Data()[i+1][0] != &packet[0] || s.buf.Len() != 0 {
			t.Fatal("borrowed packet was copied into replay storage")
		}
		domain, isQUIC, err := s.SniffUdp()
		if !bytes.Equal(packet, original) {
			t.Fatal("sniffing changed the packet to be replayed")
		}
		if !isQUIC {
			t.Fatal("QUIC Initial was not recognized")
		}
		if i == 0 {
			if !errors.Is(err, ErrNotFound) || !s.NeedMore() {
				t.Fatalf("incomplete sniff: %v, needMore=%v", err, s.NeedMore())
			}
		} else if err != nil || domain != "i.ytimg.com" {
			t.Fatalf("complete sniff: %q, %v", domain, err)
		}
	}
}

func TestBorrowedQUICInitialWithoutCryptoNeedsMore(t *testing.T) {
	for name, payload := range map[string][]byte{
		"padding": {0, 0, 0, 0},
		"ping":    {1},
		"ack":     {2, 0, 0, 0, 0},
	} {
		t.Run(name, func(t *testing.T) {
			s := NewPacketSniffer(nil)
			defer s.Close()
			s.AppendBorrowedData(testQUICV2Initial(t, payload))
			_, isQUIC, err := s.SniffUdp()
			if !isQUIC || !errors.Is(err, ErrNotFound) || !s.NeedMore() {
				t.Fatalf("Initial without CRYPTO: isQUIC=%v err=%v needMore=%v", isQUIC, err, s.NeedMore())
			}
		})
	}
}
