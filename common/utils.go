/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/daeuniverse/dae/common/consts"
)

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
