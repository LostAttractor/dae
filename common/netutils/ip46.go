/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"context"
	"net"
	"net/netip"
)

type Ip46 struct {
	Ip4 netip.Addr
	Ip6 netip.Addr
}

func (i *Ip46) IsValid() bool {
	return i.Ip4.IsValid() || i.Ip6.IsValid()
}

func FromAddr(addr netip.Addr) (ip46 *Ip46) {
	ip46 = new(Ip46)
	if addr.Is4() || addr.Is4In6() {
		ip46.Ip4 = addr
	} else {
		ip46.Ip6 = addr
	}
	return
}

func ResolveIp46(host string) (ipv46 *Ip46, err error) {
	addrs, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", host)
	if err != nil {
		return
	}
	ipv46 = new(Ip46)
	for _, addr := range addrs {
		if ipv46.Ip4.IsValid() {
			break
		}
		if addr.Is4() || addr.Is4In6() {
			ipv46.Ip4 = addr
		}
	}
	for _, addr := range addrs {
		if ipv46.Ip6.IsValid() {
			break
		}
		if addr.Is6() {
			ipv46.Ip6 = addr
		}
	}
	return
}
