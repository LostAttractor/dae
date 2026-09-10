/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/membuffer"
	"github.com/stretchr/testify/require"
)

func TestMITMPacketPairDatagrams(t *testing.T) {
	for _, tc := range []struct{ client, destination string }{
		{"192.0.2.10:50000", "198.51.100.10:443"},
		{"[2001:db8::1]:50000", "[2001:db8::2]:443"},
	} {
		t.Run(tc.client, func(t *testing.T) {
			client := netip.MustParseAddrPort(tc.client)
			destination := netip.MustParseAddrPort(tc.destination)
			ingress, server := newMITMPacketPair(client, destination)
			t.Cleanup(func() { _ = ingress.Close() })
			if ingress.LocalAddr().String() != tc.client || server.LocalAddr().String() != tc.destination {
				t.Fatalf("incorrect local addresses: %v, %v", ingress.LocalAddr(), server.LocalAddr())
			}
			for _, direction := range []struct{ writer, reader net.PacketConn }{{ingress, server}, {server, ingress}} {
				payload := []byte("original packet")
				if n, err := direction.writer.WriteTo(payload, direction.reader.LocalAddr()); err != nil || n != len(payload) {
					t.Fatalf("write: n=%d, err=%v", n, err)
				}
				payload[0] = 'X'
				buf := make([]byte, 128)
				n, from, err := direction.reader.ReadFrom(buf)
				if err != nil || string(buf[:n]) != "original packet" || from.String() != direction.writer.LocalAddr().String() {
					t.Fatalf("read: payload=%q, from=%v, err=%v", buf[:n], from, err)
				}
				// Truncating one UDP datagram must not spill bytes into the next.
				_, _ = direction.writer.WriteTo([]byte("long packet"), direction.reader.LocalAddr())
				_, _ = direction.writer.WriteTo([]byte("next"), direction.reader.LocalAddr())
				n, _, err = direction.reader.ReadFrom(buf[:3])
				if err != nil || string(buf[:n]) != "lon" {
					t.Fatalf("truncated read: %q, %v", buf[:n], err)
				}
				n, _, err = direction.reader.ReadFrom(buf)
				if err != nil || string(buf[:n]) != "next" {
					t.Fatalf("next datagram: %q, %v", buf[:n], err)
				}
			}
		})
	}
}

func TestUDPPacketMemorySharedByIngressAndMITM(t *testing.T) {
	budget := membuffer.NewBudget(16)
	p := newUdpTaskPool[int]()
	p.memory = budget
	t.Cleanup(p.close)
	started, unblock := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(unblock) }) }
	t.Cleanup(release)
	require.True(t, p.emit(1, []byte("12345"), func([]byte) udpTask {
		return func() { close(started); <-unblock }
	}))
	<-started

	client, dest := netip.MustParseAddrPort("192.0.2.1:5000"), netip.MustParseAddrPort("198.51.100.1:443")
	first, firstPeer := newMITMPacketPair(client, dest)
	second, secondPeer := newMITMPacketPair(client, dest)
	first.(*mitmPacketConn).pair.memory = budget
	second.(*mitmPacketConn).pair.memory = budget
	t.Cleanup(func() { _ = first.Close(); _ = second.Close() })
	_, err := first.WriteTo([]byte("abcde"), firstPeer.LocalAddr())
	require.NoError(t, err)
	require.EqualValues(t, 16, budget.Status().Used)
	// Another association cannot allocate beyond the shared budget. Like a
	// full UDP queue, overload reports a successful send followed by packet loss.
	n, err := second.WriteTo([]byte("lost"), secondPeer.LocalAddr())
	require.NoError(t, err)
	require.Equal(t, 4, n)
	require.Zero(t, secondPeer.(*mitmPacketConn).count)
	require.EqualValues(t, 16, budget.Status().Peak)
	// A truncated read still releases the entire datagram allocation.
	buf := make([]byte, 2)
	n, _, err = firstPeer.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "ab", string(buf[:n]))
	require.EqualValues(t, 8, budget.Status().Used)
	release()
	p.close()
	require.Zero(t, budget.Status().Used)
	// Closing either side releases queued datagrams in both directions.
	_, err = second.WriteTo([]byte("inbound"), secondPeer.LocalAddr())
	require.NoError(t, err)
	_, err = secondPeer.WriteTo([]byte("outbound"), second.LocalAddr())
	require.NoError(t, err)
	require.EqualValues(t, 16, budget.Status().Used)
	require.NoError(t, second.Close())
	require.NoError(t, secondPeer.Close())
	require.Zero(t, budget.Status().Used)
}

func TestMITMPacketPairBounds(t *testing.T) {
	ingress, server := newMITMPacketPair(netip.MustParseAddrPort("192.0.2.1:50000"), netip.MustParseAddrPort("198.51.100.1:443"))
	t.Cleanup(func() { _ = ingress.Close() })
	for _, addr := range []net.Addr{nil, &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 444}, &net.UDPAddr{IP: net.ParseIP("198.51.100.2"), Port: 443}, &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 443}} {
		if n, err := ingress.WriteTo([]byte("wrong peer"), addr); n != 0 || err == nil {
			t.Fatalf("accepted unexpected peer %v: n=%d, err=%v", addr, n, err)
		}
	}
	if n, err := ingress.WriteTo(make([]byte, mitmPacketMaxSize+1), server.LocalAddr()); n != 0 || !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("oversize datagram: n=%d, err=%v", n, err)
	}
	payload := bytes.Repeat([]byte{42}, mitmPacketMaxSize)
	if n, err := ingress.WriteTo(payload, server.LocalAddr()); n != len(payload) || err != nil {
		t.Fatalf("maximum datagram: n=%d, err=%v", n, err)
	}
	buf := make([]byte, mitmPacketMaxSize)
	if n, _, err := server.ReadFrom(buf); n != len(payload) || err != nil || !bytes.Equal(buf, payload) {
		t.Fatalf("maximum datagram read: n=%d, err=%v", n, err)
	}
	for i := 0; i < mitmPacketQueueSize+10; i++ {
		if n, err := ingress.WriteTo([]byte{byte(i)}, server.LocalAddr()); n != 1 || err != nil {
			t.Fatalf("queued write %d: n=%d, err=%v", i, n, err)
		}
	}
	for i := 0; i < mitmPacketQueueSize; i++ {
		if n, _, err := server.ReadFrom(buf); n != 1 || err != nil || buf[0] != byte(i) {
			t.Fatalf("queued read %d: n=%d, data=%v, err=%v", i, n, buf[:n], err)
		}
	}
	_ = server.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, _, err := server.ReadFrom(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("overflow packets were not dropped: %v", err)
	}
}

func TestMITMPacketPairDeadlines(t *testing.T) {
	ingress, server := newMITMPacketPair(netip.MustParseAddrPort("192.0.2.1:50000"), netip.MustParseAddrPort("198.51.100.1:443"))
	t.Cleanup(func() { _ = ingress.Close() })
	read := func() <-chan error {
		result := make(chan error, 1)
		go func() {
			_, _, err := server.ReadFrom(make([]byte, 32))
			result <- err
		}()
		return result
	}
	await := func(result <-chan error, want error) {
		t.Helper()
		select {
		case err := <-result:
			if !errors.Is(err, want) {
				t.Fatalf("read error=%v; want %v", err, want)
			}
		case <-time.After(time.Second):
			t.Fatal("read was not released")
		}
	}
	// Updating a deadline interrupts an already pending read.
	result := read()
	_ = server.SetReadDeadline(time.Now().Add(-time.Second))
	await(result, os.ErrDeadlineExceeded)
	if _, err := server.WriteTo([]byte("response"), ingress.LocalAddr()); err != nil {
		t.Fatalf("read deadline affected writes: %v", err)
	}
	// Both extending and clearing a deadline must invalidate its old timer.
	for _, clear := range []bool{false, true} {
		_ = server.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		result = read()
		deadline := time.Now().Add(time.Second)
		if clear {
			deadline = time.Time{}
		}
		_ = server.SetReadDeadline(deadline)
		select {
		case err := <-result:
			t.Fatalf("updated deadline expired early: %v", err)
		case <-time.After(40 * time.Millisecond):
		}
		_, _ = ingress.WriteTo([]byte("request"), server.LocalAddr())
		await(result, nil)
	}
	_ = ingress.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, err := ingress.WriteTo([]byte("request"), server.LocalAddr()); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write deadline was ignored: %v", err)
	}
	_ = ingress.SetWriteDeadline(time.Time{})
	if _, err := ingress.WriteTo([]byte("request"), server.LocalAddr()); err != nil {
		t.Fatalf("cleared write deadline still active: %v", err)
	}
	_ = server.SetDeadline(time.Now().Add(-time.Second))
	await(read(), os.ErrDeadlineExceeded)
	if _, err := server.WriteTo([]byte("response"), ingress.LocalAddr()); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("SetDeadline did not affect write: %v", err)
	}
	_ = server.SetDeadline(time.Time{})
	await(read(), nil)
}

func TestMITMPacketPairClose(t *testing.T) {
	ingress, server := newMITMPacketPair(netip.MustParseAddrPort("192.0.2.1:50000"), netip.MustParseAddrPort("198.51.100.1:443"))
	results := make(chan error, 4)
	for _, conn := range []net.PacketConn{ingress, server, ingress, server} {
		go func() {
			_, _, err := conn.ReadFrom(make([]byte, 32))
			results <- err
		}()
	}
	var group sync.WaitGroup
	for _, conn := range []net.PacketConn{ingress, server, ingress, server} {
		group.Go(func() { _ = conn.Close() })
	}
	group.Wait()
	for i := 0; i < 4; i++ {
		select {
		case err := <-results:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("read after close: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("close did not release pending reader")
		}
	}
	for _, conn := range []net.PacketConn{ingress, server} {
		if _, err := conn.WriteTo([]byte("closed"), conn.LocalAddr()); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("write after close: %v", err)
		}
		for _, setter := range []func(time.Time) error{conn.SetDeadline, conn.SetReadDeadline, conn.SetWriteDeadline} {
			if err := setter(time.Time{}); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("set deadline after close: %v", err)
			}
		}
	}
}

func TestMITMPacketPairConcurrent(t *testing.T) {
	ingress, server := newMITMPacketPair(netip.MustParseAddrPort("192.0.2.1:50000"), netip.MustParseAddrPort("198.51.100.1:443"))
	t.Cleanup(func() { _ = ingress.Close() })
	for _, direction := range []struct{ writer, reader net.PacketConn }{{ingress, server}, {server, ingress}} {
		_ = direction.reader.SetReadDeadline(time.Now().Add(time.Second))
		var group sync.WaitGroup
		results := make(chan byte, 32)
		for i := range 32 {
			group.Go(func() {
				if _, err := direction.writer.WriteTo([]byte{byte(i)}, direction.reader.LocalAddr()); err != nil {
					t.Errorf("concurrent write: %v", err)
				}
			})
			group.Go(func() {
				buf := make([]byte, 1)
				if n, _, err := direction.reader.ReadFrom(buf); err != nil || n != 1 {
					t.Errorf("concurrent read: n=%d, err=%v", n, err)
					return
				}
				results <- buf[0]
			})
		}
		group.Wait()
		close(results)
		seen := make(map[byte]bool)
		for value := range results {
			if seen[value] {
				t.Fatalf("duplicate concurrent datagram: %d", value)
			}
			seen[value] = true
		}
		if len(seen) != 32 {
			t.Fatalf("concurrent delivery lost datagrams: got %d, want 32", len(seen))
		}
	}
}
