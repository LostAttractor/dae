//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestShouldTryRawUDPFallback(t *testing.T) {
	v4From := netip.MustParseAddrPort("127.0.0.2:53")
	v4To := netip.MustParseAddrPort("127.0.0.1:1234")
	v6From := netip.MustParseAddrPort("[::1]:53")
	v6To := netip.MustParseAddrPort("[::1]:1234")
	tests := []struct {
		name       string
		err        error
		from, to   netip.AddrPort
		wantResult bool
	}{
		{name: "IPv4 address in use", err: unix.EADDRINUSE, from: v4From, to: v4To, wantResult: true},
		{name: "IPv6 address unavailable", err: unix.EADDRNOTAVAIL, from: v6From, to: v6To, wantResult: true},
		{name: "wrapped error", err: fmtWrap(unix.EADDRINUSE), from: v4From, to: v4To, wantResult: true},
		{name: "family mismatch", err: unix.EADDRINUSE, from: v4From, to: v6To},
		{name: "non DNS source", err: unix.EADDRINUSE, from: netip.MustParseAddrPort("127.0.0.2:5353"), to: v4To},
		{name: "permission error", err: unix.EPERM, from: v4From, to: v4To},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldTryRawUDPFallback(tt.err, tt.from, tt.to); got != tt.wantResult {
				t.Fatalf("shouldTryRawUDPFallback() = %v, want %v", got, tt.wantResult)
			}
		})
	}
}

func fmtWrap(err error) error { return &net.OpError{Op: "bind", Net: "udp", Err: err} }

func TestRawUDPChecksums(t *testing.T) {
	udp4 := make([]byte, 8+5)
	copy(udp4[8:], "hello")
	checksum4 := udp4Checksum(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), udp4)
	udp4[6], udp4[7] = byte(checksum4>>8), byte(checksum4)
	if got := udp4Checksum(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), udp4); got != 0 {
		t.Fatalf("IPv4 checksum verification = %#x, want 0", got)
	}

	udp6 := make([]byte, 8+4)
	copy(udp6[8:], "test")
	checksum6 := udp6Checksum(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"), udp6)
	udp6[6], udp6[7] = byte(checksum6>>8), byte(checksum6)
	if got := udp6Checksum(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"), udp6); got != 0 {
		t.Fatalf("IPv6 checksum verification = %#x, want 0", got)
	}
}

func TestRawUDPPayloadBounds(t *testing.T) {
	v4From := netip.MustParseAddrPort("192.0.2.1:53")
	v4To := netip.MustParseAddrPort("192.0.2.2:1234")
	v6From := netip.MustParseAddrPort("[2001:db8::1]:53")
	v6To := netip.MustParseAddrPort("[2001:db8::2]:1234")

	if maxUDPv4Payload != 65507 || maxUDPv6Payload != 65527 {
		t.Fatalf("payload limits: IPv4=%d IPv6=%d", maxUDPv4Payload, maxUDPv6Payload)
	}
	if packet, err := buildUDPv4Packet(make([]byte, maxUDPv4Payload), v4From, v4To); err != nil || len(packet) != maxUDPv4Payload+8 {
		t.Fatalf("maximum IPv4 payload: len=%d err=%v", len(packet), err)
	}
	if _, err := buildUDPv4Packet(make([]byte, maxUDPv4Payload+1), v4From, v4To); err == nil {
		t.Fatal("oversized IPv4 payload was accepted")
	}
	if packet, err := buildUDPv6Packet(make([]byte, maxUDPv6Payload), v6From, v6To); err != nil || len(packet) != maxUDPv6Payload+8 {
		t.Fatalf("maximum IPv6 payload: len=%d err=%v", len(packet), err)
	}
	if _, err := buildUDPv6Packet(make([]byte, maxUDPv6Payload+1), v6From, v6To); err == nil {
		t.Fatal("oversized IPv6 payload was accepted")
	}
}

func TestRawUDPv6SockaddrPreservesNumericZone(t *testing.T) {
	addr := netip.MustParseAddr("fe80::1%42")
	sockaddr, err := rawUDPv6Sockaddr(addr)
	if err != nil {
		t.Fatal(err)
	}
	if sockaddr.ZoneId != 42 || sockaddr.Addr != addr.As16() {
		t.Fatalf("sockaddr = %+v, want zone 42 and address %v", sockaddr, addr)
	}
}

func TestRawUDPv6SockaddrResolvesNamedZone(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) == 0 {
		t.Skipf("no network interface available: %v", err)
	}
	addr := netip.MustParseAddr("fe80::1%" + interfaces[0].Name)
	sockaddr, err := rawUDPv6Sockaddr(addr)
	if err != nil {
		t.Fatal(err)
	}
	if sockaddr.ZoneId != uint32(interfaces[0].Index) {
		t.Fatalf("zone = %d, want interface index %d", sockaddr.ZoneId, interfaces[0].Index)
	}
}

func TestRawUDPSocketOptions(t *testing.T) {
	if rawUDPSocketType&unix.SOCK_NONBLOCK == 0 {
		t.Fatal("raw UDP socket is not nonblocking")
	}
	tests := []struct {
		name          string
		family        int
		level, option int
		want          int
	}{
		{name: "IPv4", family: unix.AF_INET, level: unix.IPPROTO_IP, option: unix.IP_MTU_DISCOVER, want: unix.IP_PMTUDISC_DONT},
		{name: "IPv6", family: unix.AF_INET6, level: unix.IPPROTO_IPV6, option: unix.IPV6_MTU_DISCOVER, want: unix.IPV6_PMTUDISC_DONT},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fd, err := unix.Socket(tt.family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				if tt.family == unix.AF_INET6 && (errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EPROTONOSUPPORT)) {
					t.Skipf("IPv6 unavailable: %v", err)
				}
				t.Fatal(err)
			}
			defer unix.Close(fd)
			if err := enableRawUDPFragmentation(fd, tt.family); err != nil {
				t.Fatal(err)
			}
			got, err := unix.GetsockoptInt(fd, tt.level, tt.option)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("path MTU discovery = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSendRawUDPPacketRetriesAfterPoll(t *testing.T) {
	sendCalls := 0
	pollCalls := 0
	err := sendRawUDPPacketWith(
		42,
		[]byte("packet"),
		&unix.SockaddrInet4{},
		25*time.Millisecond,
		func(fd int, packet []byte, flags int, _ unix.Sockaddr) error {
			sendCalls++
			if fd != 42 || string(packet) != "packet" || flags != unix.MSG_DONTWAIT {
				t.Fatalf("unexpected sendto call: fd=%d packet=%q flags=%d", fd, packet, flags)
			}
			if sendCalls == 1 {
				return unix.EAGAIN
			}
			return nil
		},
		func(fds []unix.PollFd, timeout int) (int, error) {
			pollCalls++
			if len(fds) != 1 || fds[0].Fd != 42 || fds[0].Events != unix.POLLOUT {
				t.Fatalf("unexpected poll fds: %#v", fds)
			}
			if timeout <= 0 || timeout > 25 {
				t.Fatalf("poll timeout = %dms, want 1..25ms", timeout)
			}
			fds[0].Revents = unix.POLLOUT
			return 1, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if sendCalls != 2 || pollCalls != 1 {
		t.Fatalf("send calls=%d poll calls=%d, want 2 and 1", sendCalls, pollCalls)
	}
}

func TestSendRawUDPPacketPollTimeoutIsBounded(t *testing.T) {
	const bound = 20 * time.Millisecond
	pollCalls := 0
	err := sendRawUDPPacketWith(
		42,
		nil,
		&unix.SockaddrInet4{},
		bound,
		func(int, []byte, int, unix.Sockaddr) error { return unix.EWOULDBLOCK },
		func(_ []unix.PollFd, timeout int) (int, error) {
			pollCalls++
			if timeout <= 0 || timeout > int(bound/time.Millisecond) {
				t.Fatalf("poll timeout = %dms, want 1..%dms", timeout, bound/time.Millisecond)
			}
			return 0, nil
		},
	)
	if !errors.Is(err, unix.EAGAIN) {
		t.Fatalf("send error = %v, want EAGAIN", err)
	}
	if pollCalls != 1 {
		t.Fatalf("poll calls = %d, want 1", pollCalls)
	}
}

func TestRawUDPHostSysctlSettings(t *testing.T) {
	want := map[string]string{
		"net.ipv4.conf.dae0.rp_filter":      "2",
		"net.ipv4.conf.dae0.src_valid_mark": "1",
		"net.ipv4.conf.dae0.accept_local":   "1",
	}
	settings := rawUDPHostSysctlSettings()
	if len(settings) != len(want) {
		t.Fatalf("host sysctl count = %d, want %d: %#v", len(settings), len(want), settings)
	}
	for _, setting := range settings {
		if value, ok := want[setting.key]; !ok || value != setting.value {
			t.Fatalf("unexpected host sysctl: key=%q value=%q", setting.key, setting.value)
		}
		delete(want, setting.key)
	}
	if len(want) != 0 {
		t.Fatalf("missing host sysctls: %#v", want)
	}
}

func TestSendUDPv4RawDirect(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("raw socket test requires root")
	}
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conflict, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conflict.Close()
	sourcePort := conflict.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	from := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), sourcePort)
	to := client.LocalAddr().(*net.UDPAddr).AddrPort()
	if err := sendUDPv4RawDirect([]byte("hello"), from, to, 0); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("raw socket capability unavailable: %v", err)
		}
		t.Fatal(err)
	}
	assertRawUDPPacket(t, client, from)
}

func TestSendUDPv6RawDirect(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("raw socket test requires root")
	}
	client, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 unavailable: %v", err)
	}
	defer client.Close()
	conflict, err := net.ListenPacket("udp6", "[::]:0")
	if err != nil {
		t.Skipf("IPv6 wildcard bind unavailable: %v", err)
	}
	defer conflict.Close()
	sourcePort := conflict.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	from := netip.AddrPortFrom(netip.IPv6Loopback(), sourcePort)
	to := client.LocalAddr().(*net.UDPAddr).AddrPort()
	if err := sendUDPv6RawDirect([]byte("hello"), from, to, 0); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("raw socket capability unavailable: %v", err)
		}
		t.Fatal(err)
	}
	assertRawUDPPacket(t, client, from)
}

func assertRawUDPPacket(t *testing.T, client net.PacketConn, from netip.AddrPort) {
	t.Helper()
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, addr, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "hello" {
		t.Fatalf("payload = %q, want hello", got)
	}
	if got := addr.(*net.UDPAddr).AddrPort(); got != from {
		t.Fatalf("source = %v, want %v", got, from)
	}
}
