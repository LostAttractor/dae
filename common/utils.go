/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/daeuniverse/dae/common/consts"
)

func ARangeU32(n uint32) []uint32 {
	ret := make([]uint32, n)
	for i := range n {
		ret[i] = i
	}
	return ret
}

func Ipv6ByteSliceToUint32Array(_ip []byte) (ip [4]uint32) {
	for j := 0; j < 16; j += 4 {
		ip[j/4] = binary.NativeEndian.Uint32(_ip[j : j+4])
	}
	return ip
}

func Deduplicate(list []string) []string {
	if list == nil {
		return nil
	}
	res := make([]string, 0, len(list))
	m := make(map[string]struct{})
	for _, v := range list {
		if _, ok := m[v]; ok {
			continue
		}
		m[v] = struct{}{}
		res = append(res, v)
	}
	return res
}

func EnsureFileInSubDir(filePath string, dir string) (err error) {
	fileDir := filepath.Dir(filePath)
	if len(dir) == 0 {
		return fmt.Errorf("bad dir: %v", dir)
	}
	rel, err := filepath.Rel(dir, fileDir)
	if err != nil {
		return err
	}
	if strings.HasPrefix(rel, "..") {
		return fmt.Errorf("file is out of scope: %v", rel)
	}
	return nil
}

func ConvergeAddrPort(addrPort netip.AddrPort) netip.AddrPort {
	if addrPort.Addr().Is4In6() {
		return netip.AddrPortFrom(netip.AddrFrom4(addrPort.Addr().As4()), addrPort.Port())
	}
	return addrPort
}

// Htons converts a uint16 from host byte order to network byte order.
func Htons(i uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], i)
	return binary.NativeEndian.Uint16(b[:])
}

// Ntohs converts a uint16 from network byte order to host byte order.
func Ntohs(i uint16) uint16 {
	return Htons(i)
}

const InternalSoMarkFromDae uint32 = 0x100

// EffectiveSoMarkFromDae returns the mark used for dae's own sockets. A
// reserved default lets policy-routing rules identify dae's own sockets when
// so_mark_from_dae is left at zero.
func EffectiveSoMarkFromDae(mark uint32) uint32 {
	if mark != 0 {
		return mark
	}
	return InternalSoMarkFromDae
}

func ValidateSoMarkFromDae(mark uint32) error {
	if mark&consts.TproxyMark != 0 {
		return fmt.Errorf("so_mark_from_dae %#x contains reserved tproxy mark %#x", mark, consts.TproxyMark)
	}
	return nil
}
