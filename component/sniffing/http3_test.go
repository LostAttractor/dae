/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	quic "github.com/daeuniverse/quic-go"
)

func TestSniffHTTP3Initial(t *testing.T) {
	largeProtocols := make([]string, 10)
	for i := range largeProtocols {
		largeProtocols[i] = strings.Repeat(string(rune('a'+i)), 200)
	}
	largeProtocols = append(largeProtocols, "h3")
	for _, version := range []quic.Version{quic.Version1, quic.Version2} {
		for _, tc := range []struct {
			name       string
			serverName string
			protocols  []string
			wantHTTP3  bool
			fragmented bool
		}{
			{"h3", "video.example", []string{"h3"}, true, false},
			{"other QUIC", "video.example", []string{"custom-quic"}, false, false},
			{"IP without SNI", "127.0.0.1", []string{"h3"}, true, false},
			{"fragmented ClientHello", "video.example", largeProtocols, true, true},
		} {
			t.Run(version.String()+"/"+tc.name, func(t *testing.T) {
				sniffer, packets := sniffHTTP3ClientInitial(t, tc.serverName, tc.protocols, version)
				if sniffer.IsHTTP3() != tc.wantHTTP3 {
					t.Fatalf("IsHTTP3=%v; want %v", sniffer.IsHTTP3(), tc.wantHTTP3)
				}
				if sniffer.NeedMore() {
					t.Fatal("complete ClientHello still requests more datagrams")
				}
				wantDomain := tc.serverName
				if tc.name == "IP without SNI" {
					wantDomain = ""
				}
				if sniffer.sniffed != wantDomain {
					hello, _ := sniffer.quicCryptos.Bytes()
					extensions, extensionErr := clientHelloExtensions(hello)
					var sniErr error
					if extensionErr == nil {
						_, sniErr = findSniExtension(extensions)
					}
					_, dataErr := sniffer.quicCryptos.Bytes()
					t.Fatalf("SNI=%q; want %q; packets=%d; extensions=%v; SNI parse=%v; data=%v", sniffer.sniffed, wantDomain, packets, extensionErr, sniErr, dataErr)
				}
				if tc.fragmented && packets < 2 {
					t.Fatalf("large ClientHello unexpectedly fit in %d datagram", packets)
				}
			})
		}
	}
}

func TestSniffHTTP3ReorderedInitial(t *testing.T) {
	// Keep a hole between the first and last CRYPTO fragments. Seeing the
	// complete length and an early SNI does not mean the ClientHello is complete.
	protocols := make([]string, 15)
	for i := range protocols {
		protocols[i] = strings.Repeat(string(rune('a'+i)), 200)
	}
	protocols = append(protocols, "h3")
	for _, version := range []quic.Version{quic.Version1, quic.Version2} {
		t.Run(version.String(), func(t *testing.T) {
			original, _ := sniffHTTP3ClientInitial(t, "video.example", protocols, version)
			packets := original.Data()[1:] // NewPacketSniffer's empty seed is not a datagram.
			if len(packets) < 3 {
				t.Fatalf("need a middle fragment to omit, got %d datagrams", len(packets))
			}
			reordered := NewPacketSniffer(nil)
			defer reordered.Close()
			for _, packet := range [][]byte{packets[len(packets)-1], packets[0]} {
				reordered.AppendData(packet)
				_, _, _ = reordered.SniffUdp()
				if !reordered.NeedMore() || reordered.IsHTTP3() {
					t.Fatal("incomplete, reordered ClientHello was accepted")
				}
			}
			var domain string
			for _, packet := range packets[1 : len(packets)-1] {
				reordered.AppendData(packet)
				domain, _, _ = reordered.SniffUdp()
			}
			if domain != "video.example" || reordered.NeedMore() || !reordered.IsHTTP3() {
				t.Fatalf("completed reassembly: domain=%q need_more=%t h3=%t", domain, reordered.NeedMore(), reordered.IsHTTP3())
			}
		})
	}
}

// sniffHTTP3ClientInitial collects real protected QUIC Initial datagrams on
// loopback. No server handshake is needed: only the client's first flight is
// decrypted by the sniffer, then the pending client dial is cancelled.
func sniffHTTP3ClientInitial(t *testing.T, serverName string, protocols []string, version quic.Version) (*Sniffer, int) {
	t.Helper()
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	finished := make(chan error, 1)
	go func() {
		conn, err := quic.Dial(ctx, client, server.LocalAddr(), &tls.Config{
			ServerName: serverName, NextProtos: protocols,
			CurvePreferences: []tls.CurveID{tls.X25519},
		}, &quic.Config{Versions: []quic.Version{version}, InitialPacketSize: 1200})
		if conn != nil {
			_ = conn.CloseWithError(0, "test complete")
		}
		finished <- err
	}()
	defer func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Error("QUIC dial did not stop after cancellation")
		}
	}()
	deadline, _ := ctx.Deadline()
	_ = server.SetReadDeadline(deadline)
	sniffer := NewPacketSniffer(nil)
	t.Cleanup(func() { _ = sniffer.Close() })
	buf := make([]byte, 65535)
	for packets := 1; packets <= packetSniffingMaxPackets; packets++ {
		n, _, err := server.ReadFrom(buf)
		if err != nil {
			t.Fatalf("collect Initial datagram %d: %v", packets, err)
		}
		sniffer.AppendData(buf[:n])
		_, isQUIC, sniffErr := sniffer.SniffUdp()
		if !isQUIC {
			t.Fatalf("datagram %d was not identified as QUIC: %v", packets, sniffErr)
		}
		if sniffErr != nil && !errors.Is(sniffErr, ErrNotFound) {
			t.Fatalf("sniff datagram %d: %v", packets, sniffErr)
		}
		if hello, err := sniffer.quicCryptos.Bytes(); err == nil && len(hello) >= 4 {
			length := int(hello[1])<<16 | int(hello[2])<<8 | int(hello[3])
			if len(hello) == length+4 {
				return sniffer, packets
			}
		}
		if !sniffer.NeedMore() || sniffer.IsHTTP3() {
			t.Fatalf("incomplete ClientHello: NeedMore=%v, IsHTTP3=%v", sniffer.NeedMore(), sniffer.IsHTTP3())
		}
	}
	t.Fatal("ClientHello exceeded packet sniffing limit")
	return nil, 0
}

func TestHTTP3ALPNValidation(t *testing.T) {
	extension := func(data []byte) []byte {
		buf := make([]byte, 4, 4+len(data))
		binary.BigEndian.PutUint16(buf, 16)
		binary.BigEndian.PutUint16(buf[2:], uint16(len(data)))
		return append(buf, data...)
	}
	valid := extension([]byte{0, 3, 2, 'h', '3'})
	for _, tc := range []struct {
		name string
		data []byte
		want bool
	}{
		{"h3", valid, true},
		{"preceding unrelated extension", append([]byte{42, 42, 0, 1, 7}, valid...), true},
		{"multiple protocols", extension([]byte{0, 6, 2, 'h', '2', 2, 'h', '3'}), true},
		{"h3 prefix is insufficient", extension([]byte{0, 4, 3, 'h', '3', '0'}), false},
		{"empty list", extension([]byte{0, 0}), false},
		{"list length mismatch", extension([]byte{0, 4, 2, 'h', '3'}), false},
		{"protocol length mismatch", extension([]byte{0, 3, 3, 'h', '3'}), false},
		{"zero length protocol after h3", extension([]byte{0, 4, 2, 'h', '3', 0}), false},
		{"truncated protocol after h3", extension([]byte{0, 5, 2, 'h', '3', 2, 'h'}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasHTTP3ALPN(tc.data); got != tc.want {
				t.Fatalf("hasHTTP3ALPN(%x)=%v; want %v", tc.data, got, tc.want)
			}
		})
	}
	for length := 0; length < len(valid); length++ {
		if hasHTTP3ALPN(valid[:length]) {
			t.Fatalf("truncated extension identified as h3: %x", valid[:length])
		}
	}
}
