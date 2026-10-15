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

func resolveIPAddrWithResolver(resolver *net.Resolver, address string) (*net.IPAddr, int, error) {
	host, _port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, 0, err
	}
	port, err := strconv.ParseUint(_port, 10, 16)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid port: %v", _port)
	}
	addrs, err := resolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		return nil, 0, err
	}

	return &addrs[0], int(port), nil
}

func ResolveUDPAddrWithResolver(resolver *net.Resolver, address string) (*net.UDPAddr, error) {
	return ResolveUDPAddrContext(context.Background(), resolver, "ip", address)
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

func ResolveTCPAddrWithResolver(resolver *net.Resolver, address string) (*net.TCPAddr, error) {
	addr, port, err := resolveIPAddrWithResolver(resolver, address)
	if err != nil {
		return nil, err
	}

	return &net.TCPAddr{
		IP:   addr.IP,
		Zone: addr.Zone,
		Port: port,
	}, nil
}

func ResolveIPAddr(address string) (*net.IPAddr, error) {
	return ResolveIPAddrWithResolver(net.DefaultResolver, address)
}

func ResolveUDPAddr(address string) (*net.UDPAddr, error) {
	return ResolveUDPAddrWithResolver(net.DefaultResolver, address)
}

func ResolveTCPAddr(address string) (*net.TCPAddr, error) {
	return ResolveTCPAddrWithResolver(net.DefaultResolver, address)
}
