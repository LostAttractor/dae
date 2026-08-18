/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/daeuniverse/dae/common"
)

var defaultResolverState struct {
	sync.Mutex
	configured bool
	mark       uint32
}

// InstallDefaultResolver permanently replaces net.DefaultResolver with a
// marked Go resolver. Call it only during single-threaded process startup,
// before any goroutine or library can read net.DefaultResolver. Constructors
// do not call this function, so embedders must opt in explicitly before
// constructing dae. Repeated calls with the same effective mark are idempotent.
func InstallDefaultResolver(mark uint32) error {
	mark = common.EffectiveSoMarkFromDae(mark)
	if err := common.ValidateSoMarkFromDae(mark); err != nil {
		return err
	}
	defaultResolverState.Lock()
	defer defaultResolverState.Unlock()
	if defaultResolverState.configured {
		if mark != defaultResolverState.mark {
			return fmt.Errorf("default resolver SO_MARK already configured as %#x, cannot change to %#x", defaultResolverState.mark, mark)
		}
		return nil
	}
	resolver, err := newMarkedResolver(mark)
	if err != nil {
		return err
	}
	net.DefaultResolver = resolver
	defaultResolverState.configured = true
	defaultResolverState.mark = mark
	return nil
}

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

func ParseOrResolveIp46(host string) (*Ip46, error) {
	return ParseOrResolveIp46Context(context.Background(), host)
}

func ParseOrResolveIp46Context(ctx context.Context, host string) (*Ip46, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		ipv46 := new(Ip46)
		if addr.Is4() || addr.Is4In6() {
			ipv46.Ip4 = addr
		} else if addr.Is6() {
			ipv46.Ip6 = addr
		}
		return ipv46, nil
	}
	return ResolveIp46Context(ctx, host)
}

func ResolveIp46(host string) (ipv46 *Ip46, err error) {
	return ResolveIp46Context(context.Background(), host)
}

func ResolveIp46Context(ctx context.Context, host string) (ipv46 *Ip46, err error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
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
