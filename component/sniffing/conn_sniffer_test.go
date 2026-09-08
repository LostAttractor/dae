/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestStreamSnifferHandlesSplitHeaders(t *testing.T) {
	var records []byte
	hello := tlsStreamGoogle[5:]
	for _, part := range [][]byte{hello[:2], hello[2:40], hello[40:]} {
		records = append(records, 22, 3, 3)
		records = binary.BigEndian.AppendUint16(records, uint16(len(part)))
		records = append(records, part...)
	}
	for _, test := range []struct {
		name, host string
		data       []byte
	}{
		{"HTTP", "example.com", []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody")},
		{"TLS", "www.google.com", tlsStreamGoogle},
		{"TLS records", "www.google.com", records},
	} {
		for _, split := range []int{1, 2, 3, 4, 5, 16, 30} {
			t.Run(fmt.Sprintf("%s/%d", test.name, split), func(t *testing.T) {
				reader := io.MultiReader(bytes.NewReader(test.data[:split]), bytes.NewReader(test.data[split:]))
				s := NewStreamSniffer(reader, time.Second)
				defer s.Close()
				host, err := s.SniffTcp()
				if err != nil || host != test.host {
					t.Fatalf("sniffed (%q, %v), want %q", host, err, test.host)
				}
				got, err := io.ReadAll(s)
				if err != nil || !bytes.Equal(got, test.data) {
					t.Fatalf("replay returned %d bytes, error %v; want original %d bytes", len(got), err, len(test.data))
				}
			})
		}
	}
}

func TestStreamSnifferBoundsIncompleteHTTPHeaders(t *testing.T) {
	data := append([]byte("GET / HTTP/1.1\r\nX: "), bytes.Repeat([]byte("x"), 2*streamSniffingMaxBytes)...)
	s := NewStreamSniffer(bytes.NewReader(data), time.Second)
	defer s.Close()
	if _, err := s.SniffTcp(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("oversized incomplete header error = %v", err)
	}
	got, err := io.ReadAll(s)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("oversized header replay returned %d bytes, error %v", len(got), err)
	}
}

func TestStreamSnifferRejectsHostTruncatedAtEOF(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\nHost: example")
	s := NewStreamSniffer(&dataEOFReader{data: data}, time.Second)
	defer s.Close()
	if host, err := s.SniffTcp(); host != "" || !errors.Is(err, io.EOF) {
		t.Fatalf("incomplete Host became a routing result: %q, %v", host, err)
	}
	got, err := io.ReadAll(s)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("truncated header replay returned %q, error %v", got, err)
	}
}

type readTrackingConn struct {
	net.Conn
	reads  atomic.Int32
	active atomic.Int32
}

type dataEOFReader struct {
	data []byte
}

func (r *dataEOFReader) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, io.EOF
}

func (c *readTrackingConn) Read(p []byte) (int, error) {
	c.reads.Add(1)
	c.active.Add(1)
	defer c.active.Add(-1)
	return c.Conn.Read(p)
}

func TestConnSnifferTimeoutLeavesNoReader(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	tracked := &readTrackingConn{Conn: server}
	sniffer := NewConnSniffer(tracked, 20*time.Millisecond)
	defer sniffer.Close()

	_, err := sniffer.SniffTcp()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("SniffTcp error = %v, want deadline exceeded", err)
	}
	if got := tracked.reads.Load(); got != 1 {
		t.Fatalf("Read calls = %d, want 1", got)
	}
	if got := tracked.active.Load(); got != 0 {
		t.Fatalf("active Read calls after timeout = %d, want 0", got)
	}

	if err := client.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, err := client.Write([]byte("x")); n != 0 || err == nil {
		t.Fatalf("write with no reader = (%d, %v), want timeout", n, err)
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("write error = %v, want timeout", err)
	}
}

func TestConnSnifferZeroTimeoutDoesNotRead(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	tracked := &readTrackingConn{Conn: server}
	sniffer := NewConnSniffer(tracked, 0)
	defer sniffer.Close()

	_, err := sniffer.SniffTcp()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("SniffTcp error = %v, want deadline exceeded", err)
	}
	if got := tracked.reads.Load(); got != 0 {
		t.Fatalf("Read calls = %d, want 0", got)
	}
	var prefix bytes.Buffer
	if err := sniffer.WriteBufferedTo(&prefix); err != nil {
		t.Fatal(err)
	}
	if prefix.Len() != 0 {
		t.Fatalf("buffered prefix = %q, want empty", prefix.Bytes())
	}

	payload := []byte("not consumed by sniffing")
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		writeDone <- err
	}()
	if err := tracked.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(tracked, got); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("raw payload = %q, want %q", got, payload)
	}
}

func TestConnSnifferWriteBufferedToExactlyOnce(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	sniffer := NewConnSniffer(server, time.Second)
	defer sniffer.Close()
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		writeDone <- err
	}()
	domain, err := sniffer.SniffTcp()
	if err != nil {
		t.Fatal(err)
	}
	if domain != "example.com" {
		t.Fatalf("domain = %q, want example.com", domain)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}

	var prefix bytes.Buffer
	if err := sniffer.WriteBufferedTo(&prefix); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(prefix.Bytes(), payload) {
		t.Fatalf("prefix = %q, want %q", prefix.Bytes(), payload)
	}
	prefix.Reset()
	if err := sniffer.WriteBufferedTo(&prefix); err != nil {
		t.Fatal(err)
	}
	if prefix.Len() != 0 {
		t.Fatalf("second prefix = %q, want empty", prefix.Bytes())
	}
}

func TestConnSnifferReleasesReplayBuffer(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	sniffer := NewConnSniffer(server, time.Second).(*ConnSniffer)
	defer sniffer.Close()
	prefix := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	tail := []byte("body arriving after replay")
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write(prefix)
		if err == nil {
			_, err = client.Write(tail)
		}
		writeDone <- err
	}()
	if _, err := sniffer.SniffTcp(); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(prefix)+len(tail))
	if _, err := io.ReadFull(sniffer, got[:1]); err != nil {
		t.Fatal(err)
	}
	if sniffer.buf == nil {
		t.Fatal("released buffer before all sniffed bytes were replayed")
	}
	if _, err := io.ReadFull(sniffer, got[1:len(prefix)]); err != nil {
		t.Fatal(err)
	}
	if sniffer.buf != nil {
		t.Fatal("live connection retained an exhausted sniff buffer")
	}
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(sniffer, got[len(prefix):]); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if want := append(prefix, tail...); !bytes.Equal(got, want) {
		t.Fatalf("replayed data = %q, want %q", got, want)
	}
}

func TestPacketSnifferRetainsReplayData(t *testing.T) {
	payload := []byte("not QUIC")
	sniffer := NewPacketSniffer(payload)
	defer sniffer.Close()
	_, _, _ = sniffer.SniffUdp()
	if _, err := io.ReadAll(sniffer); err != nil {
		t.Fatal(err)
	}
	if sniffer.buf == nil || !bytes.Equal(sniffer.Data()[0], payload) {
		t.Fatal("reading packet buffer invalidated packet replay data")
	}
}

func TestSnifferDeliversWholeBufferBeforeEOF(t *testing.T) {
	sniffer := NewStreamSniffer(bytes.NewReader(nil), time.Second)
	payload := bytes.Repeat([]byte("buffered"), 16*1024)
	sniffer.buf.Write(payload)
	sniffer.dataError = io.EOF
	close(sniffer.dataReady)

	got, err := io.ReadAll(sniffer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("read %d buffered bytes, want %d", len(got), len(payload))
	}
}

func TestSnifferParsesDataReturnedWithEOF(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	sniffer := NewStreamSniffer(&dataEOFReader{data: payload}, time.Second)
	domain, err := sniffer.SniffTcp()
	if err != nil {
		t.Fatal(err)
	}
	if domain != "example.com" {
		t.Fatalf("domain = %q, want example.com", domain)
	}
	got, err := io.ReadAll(sniffer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
}

func TestStreamSnifferGenericReaderTimeout(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	sniffer := NewStreamSniffer(reader, 20*time.Millisecond)
	defer sniffer.Close()

	_, err := sniffer.SniffTcp()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("SniffTcp error = %v, want deadline exceeded", err)
	}
	payload := []byte("available after sniff timeout")
	writeDone := make(chan error, 1)
	go func() {
		_, err := writer.Write(payload)
		writeDone <- err
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(sniffer, got); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
}

func TestStreamSnifferCloseInterruptsConnRead(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	tracked := &readTrackingConn{Conn: server}
	sniffer := NewStreamSniffer(tracked, time.Hour)
	done := make(chan error, 1)
	go func() {
		_, err := sniffer.SniffTcp()
		done <- err
	}()
	deadline := time.Now().Add(time.Second)
	for tracked.active.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if tracked.active.Load() == 0 {
		t.Fatal("SniffTcp did not start reading")
	}
	if err := sniffer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SniffTcp remained blocked after Close")
	}
}
