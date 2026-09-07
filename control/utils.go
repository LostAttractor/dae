/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"structs"
	"syscall"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"golang.org/x/sys/unix"
)

func IsNetError(err error) (net.Error, bool) { return errors.AsType[net.Error](err) }

// closeInBackground starts cleanup without making control-plane shutdown wait
// for transports whose Close may block. It does not guarantee cleanup completion.
func closeInBackground(closer io.Closer) {
	if closer != nil {
		go func() { _ = closer.Close() }()
	}
}

func (c *controlPlaneCore) RetrieveRoutingResult(src, dst netip.AddrPort, l4proto uint8) (result *bpfRoutingResult, err error) {
	srcIp6 := src.Addr().As16()
	dstIp6 := dst.Addr().As16()

	tuples := &bpfTuplesKey{
		Sip: struct {
			_       structs.HostLayout
			U6Addr8 [16]uint8
		}{U6Addr8: srcIp6},
		Sport: common.Htons(src.Port()),
		Dip: struct {
			_       structs.HostLayout
			U6Addr8 [16]uint8
		}{U6Addr8: dstIp6},
		Dport:   common.Htons(dst.Port()),
		L4proto: l4proto,
	}

	var routingResult bpfRoutingResult
	if err := c.bpf.RoutingTuplesMap.Lookup(tuples, &routingResult); err != nil {
		return nil, fmt.Errorf("reading map: key [%v, %v, %v]: %w", src.String(), l4proto, dst.String(), err)
	}
	return &routingResult, nil
}

func RetrieveOriginalDest(oob []byte) netip.AddrPort {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.AddrPort{}
	}
	for _, msg := range msgs {
		if msg.Header.Level == syscall.SOL_IP && msg.Header.Type == syscall.IP_RECVORIGDSTADDR {
			ip := msg.Data[4:8]
			port := binary.BigEndian.Uint16(msg.Data[2:4])
			return netip.AddrPortFrom(netip.AddrFrom4(*(*[4]byte)(ip)), port)
		} else if msg.Header.Level == syscall.SOL_IPV6 && msg.Header.Type == unix.IPV6_RECVORIGDSTADDR {
			ip := msg.Data[8:24]
			port := binary.BigEndian.Uint16(msg.Data[2:4])
			return netip.AddrPortFrom(netip.AddrFrom16(*(*[16]byte)(ip)), port)
		}
	}
	return netip.AddrPort{}
}

func checkIpforward(ifname string, ipversion consts.IpVersionStr) error {
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/forwarding", ipversion, ifname)
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if bytes.Equal(bytes.TrimSpace(b), []byte("1")) {
		return nil
	}
	return fmt.Errorf("ipforward on %v is off: %v; see docs of dae for help", ifname, path)
}

func CheckIpforward(ifname string) error {
	if err := checkIpforward(ifname, consts.IpVersionStr_4); err != nil {
		return err
	}
	if err := checkIpforward(ifname, consts.IpVersionStr_6); err != nil {
		return err
	}
	return nil
}

func setHostSysctl(name, path, value string) error {
	return setHostSysctlWith(name, value, func() ([]byte, error) {
		return os.ReadFile(path)
	}, func(value []byte) error {
		return os.WriteFile(path, value, 0644)
	})
}

func setHostSysctlWith(name, value string, read func() ([]byte, error), write func([]byte) error) error {
	current, err := read()
	if err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	if string(bytes.TrimSpace(current)) == value {
		return nil
	}
	if err := write([]byte(value)); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

func setForwarding(ifname string, ipversion consts.IpVersionStr, val string) error {
	name := fmt.Sprintf("net.ipv%v.conf.%v.forwarding", ipversion, ifname)
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/forwarding", ipversion, ifname)
	return setHostSysctl(name, path, val)
}

func SetIpv4forward(val string) error {
	return setHostSysctl("net.ipv4.ip_forward", "/proc/sys/net/ipv4/ip_forward", val)
}

func SetForwarding(ifname string, val string) error {
	if err := setForwarding(ifname, consts.IpVersionStr_4, val); err != nil {
		return err
	}
	return setForwarding(ifname, consts.IpVersionStr_6, val)
}

func checkSendRedirects(ifname string, ipversion consts.IpVersionStr) error {
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/send_redirects", ipversion, ifname)
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if bytes.Equal(bytes.TrimSpace(b), []byte("0")) {
		return nil
	}
	return fmt.Errorf("send_redirects on %v is on: %v; see docs of dae for help", ifname, path)
}

func CheckSendRedirects(ifname string) error {
	if err := checkSendRedirects(ifname, consts.IpVersionStr_4); err != nil {
		return err
	}
	return nil
}

func setSendRedirects(ifname string, ipversion consts.IpVersionStr, val string) error {
	name := fmt.Sprintf("net.ipv%v.conf.%v.send_redirects", ipversion, ifname)
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/send_redirects", ipversion, ifname)
	return setHostSysctl(name, path, val)
}

func SetSendRedirects(ifname string, val string) error {
	return setSendRedirects(ifname, consts.IpVersionStr_4, val)
}

func ProcessName2String(pname []uint8) string {
	return string(bytes.TrimRight(pname[:], string([]byte{0})))
}

func Mac2String(mac []uint8) string {
	ori := []byte(hex.EncodeToString(mac))
	// Insert ":".
	b := make([]byte, len(ori)/2*3-1)
	for i, j := 0, 0; i < len(ori); i, j = i+2, j+3 {
		copy(b[j:j+2], ori[i:i+2])
		if j+2 < len(b) {
			b[j+2] = ':'
		}
	}
	return string(b)
}
