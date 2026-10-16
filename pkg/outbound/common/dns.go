/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// BootstrapResolver resolves proxy-server addresses independently of DNS routed
// through those proxies. Embedders may install it before concurrent work starts.
var BootstrapResolver = net.DefaultResolver

func ResolveIPAddrWithResolver(resolver *net.Resolver, address string) (*net.IPAddr, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	addrs, err := resolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		return nil, err
	}
	return &addrs[0], nil
}

// ResolveUDPAddrContext resolves within one address family (ip, ip4 or ip6).
func ResolveUDPAddrContext(ctx context.Context, resolver *net.Resolver, network, address string) (*net.UDPAddr, error) {
	host, portString, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %s", portString)
	}
	addrs, err := resolver.LookupNetIP(ctx, network, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, &net.DNSError{Name: host, Err: "no suitable address", IsNotFound: true}
	}
	addr := addrs[0].Unmap()
	// LookupNetIP enforces the requested family but drops literal IPv6 zones.
	// DNS names have no zone; scoped literals retain exactly what was supplied.
	literal, _ := netip.ParseAddr(host)
	return &net.UDPAddr{
		IP:   net.IP(addr.AsSlice()),
		Zone: literal.Zone(),
		Port: int(port),
	}, nil
}
