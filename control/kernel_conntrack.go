// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func probeHostConntrack(ctx context.Context) error {
	// Socket creation and TestRun must use the same host namespace, not daens.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ctx.Err(); err != nil {
		return err
	}
	spec, err := loadBPFSpec()
	if err != nil {
		return fmt.Errorf("load conntrack probe: read embedded eBPF collection: %w", err)
	}
	program, err := loadConntrackProbe(spec)
	if err != nil {
		return err
	}
	defer program.Close()
	query := func(source, destination netip.AddrPort) (uint32, error) {
		return program.Run(&ebpf.RunOptions{Data: conntrackProbePacket(source, destination), Repeat: 1})
	}
	return runKernelChecks(ctx,
		kernelCheck{"IPv4 UDP conntrack in host namespace", func() error { return probeConntrackFamily(ctx, "udp4", query) }},
		kernelCheck{"IPv6 UDP conntrack in host namespace", func() error { return probeConntrackFamily(ctx, "udp6", query) }},
	)
}

func loadConntrackProbe(spec *ebpf.CollectionSpec) (*ebpf.Program, error) {
	program := spec.Programs["conntrack_probe"]
	if program == nil {
		return nil, errors.New("load conntrack probe: embedded conntrack_probe program is missing")
	}
	probe, err := ebpf.NewProgram(program)
	if err != nil {
		return nil, fmt.Errorf("load conntrack probe (CT kfuncs/BTF, options ABI and process capabilities): %w", explainBPFLoadError(err))
	}
	return probe, nil
}

func probeConntrackFamily(ctx context.Context, network string, query func(netip.AddrPort, netip.AddrPort) (uint32, error)) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for range 8 {
		occupied, err := probeConntrackTuple(ctx, network, query)
		if !occupied || err != nil {
			return err
		}
	}
	return errors.New("fresh tuple selection: all random loopback tuples already tracked")
}

func probeConntrackTuple(ctx context.Context, network string, query func(netip.AddrPort, netip.AddrPort) (uint32, error)) (occupied bool, err error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	loopback := net.IPv4(127, 0, 0, 1)
	if network == "udp6" {
		loopback = net.IPv6loopback
	}
	client, err := net.ListenUDP(network, &net.UDPAddr{IP: loopback})
	if err != nil {
		return false, fmt.Errorf("UDP socket: bind client: %w", err)
	}
	defer client.Close()
	server, err := net.ListenUDP(network, &net.UDPAddr{IP: loopback})
	if err != nil {
		return false, fmt.Errorf("UDP socket: bind server: %w", err)
	}
	defer server.Close()
	stop := context.AfterFunc(ctx, func() {
		client.Close()
		server.Close()
	})
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := errors.Join(client.SetDeadline(deadline), server.SetDeadline(deadline)); err != nil {
		return false, fmt.Errorf("UDP socket: set deadline: %w", err)
	}
	source := client.LocalAddr().(*net.UDPAddr).AddrPort()
	destination := server.LocalAddr().(*net.UDPAddr).AddrPort()
	lookup := func(source, destination netip.AddrPort) (uint32, error) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		result, err := query(source, destination)
		if err != nil {
			return 0, fmt.Errorf("BPF TestRun: %w", err)
		}
		if int32(result) < 0 {
			return 0, fmt.Errorf("lookup error: %w", unix.Errno(-int64(int32(result))))
		}
		if result > 2 {
			return 0, fmt.Errorf("unexpected lookup result %d", result)
		}
		return result, nil
	}
	for _, tuple := range [][2]netip.AddrPort{{source, destination}, {destination, source}} {
		result, err := lookup(tuple[0], tuple[1])
		if err != nil {
			return false, fmt.Errorf("fresh tuple lookup %s -> %s: %w", tuple[0], tuple[1], err)
		}
		if result != 0 {
			return true, nil
		}
	}
	if err := conntrackNonceRoundTrip(client, server); err != nil {
		return false, fmt.Errorf("UDP nonce round trip: %w", errors.Join(ctx.Err(), err))
	}
	for i, tuple := range [][2]netip.AddrPort{{source, destination}, {destination, source}} {
		result, err := lookup(tuple[0], tuple[1])
		direction := []string{"ORIGINAL", "REPLY"}[i]
		if err != nil {
			return false, fmt.Errorf("direction %s after UDP round trip: %w", direction, err)
		}
		if result != uint32(i+1) {
			return false, fmt.Errorf("direction %s after UDP round trip: got %d, want %d (0=lookup miss); check namespace CT hooks, NOTRACK, zone and table capacity", direction, result, i+1)
		}
	}
	return false, ctx.Err()
}

func conntrackNonceRoundTrip(client, server *net.UDPConn) error {
	var nonce [32]byte
	rand.Read(nonce[:])
	for _, pair := range [][2]*net.UDPConn{{client, server}, {server, client}} {
		sender, receiver := pair[0], pair[1]
		if _, err := sender.WriteToUDPAddrPort(nonce[:], receiver.LocalAddr().(*net.UDPAddr).AddrPort()); err != nil {
			return err
		}
		if err := readConntrackNonce(receiver, nonce[:], sender.LocalAddr().(*net.UDPAddr).AddrPort()); err != nil {
			return err
		}
	}
	return nil
}

func readConntrackNonce(receiver *net.UDPConn, nonce []byte, peer netip.AddrPort) error {
	packet := make([]byte, len(nonce)+1)
	n, from, err := receiver.ReadFromUDPAddrPort(packet)
	if err != nil {
		return err
	}
	if from != peer || !bytes.Equal(packet[:n], nonce) {
		return errors.New("unexpected UDP peer or nonce")
	}
	return nil
}

func conntrackProbePacket(source, destination netip.AddrPort) []byte {
	// TestRun only parses these headers; it never transmits the synthetic packet.
	ipSize, protocol := 20, uint16(unix.ETH_P_IP)
	if source.Addr().Is6() {
		ipSize, protocol = 40, unix.ETH_P_IPV6
	}
	packet := make([]byte, 14+ipSize+8)
	binary.BigEndian.PutUint16(packet[12:14], protocol)
	ip, udp := packet[14:14+ipSize], packet[14+ipSize:]
	if source.Addr().Is6() {
		ip[0], ip[6], ip[7] = 0x60, unix.IPPROTO_UDP, 64
		binary.BigEndian.PutUint16(ip[4:6], uint16(len(udp)))
		copy(ip[8:24], source.Addr().AsSlice())
		copy(ip[24:40], destination.Addr().AsSlice())
	} else {
		ip[0], ip[8], ip[9] = 0x45, 64, unix.IPPROTO_UDP
		binary.BigEndian.PutUint16(ip[2:4], uint16(ipSize+len(udp)))
		copy(ip[12:16], source.Addr().AsSlice())
		copy(ip[16:20], destination.Addr().AsSlice())
	}
	binary.BigEndian.PutUint16(udp[0:2], source.Port())
	binary.BigEndian.PutUint16(udp[2:4], destination.Port())
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	return packet
}
