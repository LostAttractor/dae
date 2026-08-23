//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

const (
	maxUDPv4Payload   = 1<<16 - 1 - 20 - 8
	maxUDPv6Payload   = 1<<16 - 1 - 8
	rawUDPSocketType  = unix.SOCK_RAW | unix.SOCK_CLOEXEC | unix.SOCK_NONBLOCK
	rawUDPSendTimeout = 100 * time.Millisecond
)

type rawUDPSendtoFunc func(int, []byte, int, unix.Sockaddr) error
type rawUDPPollFunc func([]unix.PollFd, int) (int, error)

func sendUDPv4RawDirect(data []byte, from, to netip.AddrPort, mark uint32) error {
	udp, err := buildUDPv4Packet(data, from, to)
	if err != nil {
		return err
	}

	fd, err := unix.Socket(unix.AF_INET, rawUDPSocketType, unix.IPPROTO_UDP)
	if err != nil {
		return fmt.Errorf("create raw IPv4 UDP socket: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TRANSPARENT, 1); err != nil {
		return fmt.Errorf("enable IP_TRANSPARENT on raw socket: %w", err)
	}
	if err := enableRawUDPFragmentation(fd, unix.AF_INET); err != nil {
		return fmt.Errorf("enable IPv4 fragmentation on raw socket: %w", err)
	}
	if mark != 0 {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(mark)); err != nil {
			return fmt.Errorf("set SO_MARK on raw socket: %w", err)
		}
	}

	fromIP := from.Addr().Unmap().As4()
	bindAddr := &unix.SockaddrInet4{Addr: fromIP}
	if err := unix.Bind(fd, bindAddr); err != nil {
		return fmt.Errorf("bind raw IPv4 UDP socket to %v: %w", from.Addr(), err)
	}

	toIP := to.Addr().Unmap().As4()
	if err := sendRawUDPPacket(fd, udp, &unix.SockaddrInet4{Addr: toIP}); err != nil {
		return fmt.Errorf("send raw IPv4 UDP packet from %v to %v: %w", from, to, err)
	}
	return nil
}

func buildUDPv4Packet(data []byte, from, to netip.AddrPort) ([]byte, error) {
	if !from.IsValid() || !to.IsValid() ||
		(!from.Addr().Is4() && !from.Addr().Is4In6()) ||
		(!to.Addr().Is4() && !to.Addr().Is4In6()) {
		return nil, fmt.Errorf("raw UDPv4 fallback requires IPv4 endpoints: from=%v to=%v", from, to)
	}
	if len(data) > maxUDPv4Payload {
		return nil, fmt.Errorf("raw UDPv4 payload is too large: %d", len(data))
	}

	udp := make([]byte, 8+len(data))
	binary.BigEndian.PutUint16(udp[0:2], from.Port())
	binary.BigEndian.PutUint16(udp[2:4], to.Port())
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], data)
	checksum := udp4Checksum(from.Addr().Unmap(), to.Addr().Unmap(), udp)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], checksum)
	return udp, nil
}

func sendUDPv4RawInDaeNetns(data []byte, from, to netip.AddrPort, mark uint32) error {
	ns := GetDaeNetns()
	if ns == nil {
		return fmt.Errorf("dae netns is not initialized")
	}
	_, err := ns.With(func() (struct{}, error) {
		return struct{}{}, sendUDPv4RawDirect(data, from, to, mark)
	})
	return err
}

func sendUDPv6RawDirect(data []byte, from, to netip.AddrPort, mark uint32) error {
	udp, err := buildUDPv6Packet(data, from, to)
	if err != nil {
		return err
	}

	fd, err := unix.Socket(unix.AF_INET6, rawUDPSocketType, unix.IPPROTO_UDP)
	if err != nil {
		return fmt.Errorf("create raw IPv6 UDP socket: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
		return fmt.Errorf("enable IPV6_TRANSPARENT on raw socket: %w", err)
	}
	if err := enableRawUDPFragmentation(fd, unix.AF_INET6); err != nil {
		return fmt.Errorf("enable IPv6 fragmentation on raw socket: %w", err)
	}
	if mark != 0 {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(mark)); err != nil {
			return fmt.Errorf("set SO_MARK on raw socket: %w", err)
		}
	}

	fromAddr, err := rawUDPv6Sockaddr(from.Addr())
	if err != nil {
		return fmt.Errorf("resolve raw IPv6 source address %v: %w", from.Addr(), err)
	}
	if err := unix.Bind(fd, fromAddr); err != nil {
		return fmt.Errorf("bind raw IPv6 UDP socket to %v: %w", from.Addr(), err)
	}

	toAddr, err := rawUDPv6Sockaddr(to.Addr())
	if err != nil {
		return fmt.Errorf("resolve raw IPv6 destination address %v: %w", to.Addr(), err)
	}
	if err := sendRawUDPPacket(fd, udp, toAddr); err != nil {
		return fmt.Errorf("send raw IPv6 UDP packet from %v to %v: %w", from, to, err)
	}
	return nil
}

func rawUDPv6Sockaddr(addr netip.Addr) (*unix.SockaddrInet6, error) {
	sockaddr := &unix.SockaddrInet6{Addr: addr.As16()}
	zone := addr.Zone()
	if zone == "" {
		return sockaddr, nil
	}
	if iface, err := net.InterfaceByName(zone); err == nil {
		sockaddr.ZoneId = uint32(iface.Index)
		return sockaddr, nil
	}
	index, err := strconv.ParseUint(zone, 10, 32)
	if err != nil {
		return nil, err
	}
	sockaddr.ZoneId = uint32(index)
	return sockaddr, nil
}

func buildUDPv6Packet(data []byte, from, to netip.AddrPort) ([]byte, error) {
	if !from.IsValid() || !to.IsValid() || !from.Addr().Is6() || from.Addr().Is4In6() ||
		!to.Addr().Is6() || to.Addr().Is4In6() {
		return nil, fmt.Errorf("raw UDPv6 fallback requires IPv6 endpoints: from=%v to=%v", from, to)
	}
	if len(data) > maxUDPv6Payload {
		return nil, fmt.Errorf("raw UDPv6 payload is too large: %d", len(data))
	}

	udp := make([]byte, 8+len(data))
	binary.BigEndian.PutUint16(udp[0:2], from.Port())
	binary.BigEndian.PutUint16(udp[2:4], to.Port())
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], data)
	checksum := udp6Checksum(from.Addr(), to.Addr(), udp)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], checksum)
	return udp, nil
}

func sendUDPv6RawInDaeNetns(data []byte, from, to netip.AddrPort, mark uint32) error {
	ns := GetDaeNetns()
	if ns == nil {
		return fmt.Errorf("dae netns is not initialized")
	}
	_, err := ns.With(func() (struct{}, error) {
		return struct{}{}, sendUDPv6RawDirect(data, from, to, mark)
	})
	return err
}

func enableRawUDPFragmentation(fd, family int) error {
	switch family {
	case unix.AF_INET:
		return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DONT)
	case unix.AF_INET6:
		return unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DONT)
	default:
		return unix.EAFNOSUPPORT
	}
}

func sendRawUDPPacket(fd int, packet []byte, to unix.Sockaddr) error {
	return sendRawUDPPacketWith(fd, packet, to, rawUDPSendTimeout, unix.Sendto, unix.Poll)
}

func sendRawUDPPacketWith(
	fd int,
	packet []byte,
	to unix.Sockaddr,
	timeout time.Duration,
	sendto rawUDPSendtoFunc,
	poll rawUDPPollFunc,
) error {
	err := sendto(fd, packet, unix.MSG_DONTWAIT, to)
	if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) {
		return err
	}

	deadline := time.Now().Add(timeout)
	pollFd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("raw UDP socket remained blocked for %v: %w", timeout, err)
		}
		pollTimeout := int((remaining + time.Millisecond - 1) / time.Millisecond)
		pollFd[0].Revents = 0
		n, pollErr := poll(pollFd, pollTimeout)
		if errors.Is(pollErr, unix.EINTR) {
			continue
		}
		if pollErr != nil {
			return fmt.Errorf("poll raw UDP socket for write: %w", pollErr)
		}
		if n == 0 {
			return fmt.Errorf("raw UDP socket remained blocked for %v: %w", timeout, err)
		}
		if pollFd[0].Revents&unix.POLLOUT == 0 {
			if pollFd[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				return fmt.Errorf("poll raw UDP socket for write returned events %#x: %w", pollFd[0].Revents, unix.EIO)
			}
			continue
		}

		err = sendto(fd, packet, unix.MSG_DONTWAIT, to)
		if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) {
			return err
		}
	}
}

func udp4Checksum(src, dst netip.Addr, udp []byte) uint16 {
	pseudo := make([]byte, 12+len(udp))
	srcIP, dstIP := src.As4(), dst.As4()
	copy(pseudo[0:4], srcIP[:])
	copy(pseudo[4:8], dstIP[:])
	pseudo[9] = unix.IPPROTO_UDP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp)))
	copy(pseudo[12:], udp)
	return internetChecksum(pseudo)
}

func udp6Checksum(src, dst netip.Addr, udp []byte) uint16 {
	pseudo := make([]byte, 40+len(udp))
	srcIP, dstIP := src.As16(), dst.As16()
	copy(pseudo[0:16], srcIP[:])
	copy(pseudo[16:32], dstIP[:])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(udp)))
	pseudo[39] = unix.IPPROTO_UDP
	copy(pseudo[40:], udp)
	return internetChecksum(pseudo)
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
