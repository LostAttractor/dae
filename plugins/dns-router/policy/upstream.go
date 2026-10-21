/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"context"
	"fmt"
	"iter"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/outbound/happyeyeballs"
)

var (
	ErrFormat = fmt.Errorf("format error")
)

type UpstreamScheme string

const (
	UpstreamScheme_TCP           UpstreamScheme = "tcp"
	UpstreamScheme_UDP           UpstreamScheme = "udp"
	UpstreamScheme_TCP_UDP       UpstreamScheme = "tcp+udp"
	upstreamScheme_TCP_UDP_Alias UpstreamScheme = "udp+tcp"
	UpstreamScheme_TLS           UpstreamScheme = "tls"
	UpstreamScheme_QUIC          UpstreamScheme = "quic"
	UpstreamScheme_HTTPS         UpstreamScheme = "https"
	upstreamScheme_H3_Alias      UpstreamScheme = "http3"
	UpstreamScheme_H3            UpstreamScheme = "h3"
)

func ParseRawUpstream(raw *url.URL) (scheme UpstreamScheme, hostname string, port uint16, path string, err error) {
	var __port string
	var __path string
	switch scheme = UpstreamScheme(raw.Scheme); scheme {
	case upstreamScheme_TCP_UDP_Alias:
		scheme = UpstreamScheme_TCP_UDP
		fallthrough
	case UpstreamScheme_TCP, UpstreamScheme_UDP, UpstreamScheme_TCP_UDP:
		__port = raw.Port()
		if __port == "" {
			__port = "53"
		}
	case upstreamScheme_H3_Alias:
		scheme = UpstreamScheme_H3
		fallthrough
	case UpstreamScheme_HTTPS, UpstreamScheme_H3:
		__port = raw.Port()
		if __port == "" {
			__port = "443"
		}
		__path = raw.Path
		if __path == "" {
			__path = "/dns-query"
		}
	case UpstreamScheme_QUIC, UpstreamScheme_TLS:
		__port = raw.Port()
		if __port == "" {
			__port = "853"
		}
	default:
		return "", "", 0, "", fmt.Errorf("unexpected scheme: %v", raw.Scheme)
	}
	_port, err := strconv.ParseUint(__port, 10, 16)
	if err != nil {
		return "", "", 0, "", fmt.Errorf("failed to parse dns_upstream port: %v", err)
	}
	port = uint16(_port)
	hostname = raw.Hostname()
	if port == 0 || hostname == "" || strings.Contains(hostname, "%") {
		return "", "", 0, "", fmt.Errorf("dns_upstream requires a host, a nonzero port and no IP zone")
	}
	return scheme, hostname, port, __path, nil
}

type Upstream struct {
	Scheme   UpstreamScheme
	Hostname string
	Port     uint16
	Path     string
	RawPath  string // Preserve escaped separators in HTTP endpoint paths.
	RawQuery string // Configured HTTP parameters, before adding the DNS query.
	*netutils.Ip46
	mu       sync.Mutex
	resolved []netip.Addr
}

func NewUpstream(ctx context.Context, upstream *url.URL) (up *Upstream, err error) {
	scheme, hostname, port, path, err := ParseRawUpstream(upstream)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var ip46 *netutils.Ip46
	if ip, err := netip.ParseAddr(hostname); err == nil {
		ip46 = new(netutils.Ip46)
		if ip = ip.Unmap(); ip.Is4() {
			ip46.Ip4 = ip
		} else {
			ip46.Ip6 = ip
		}
	}

	return &Upstream{
		Scheme:   scheme,
		Hostname: hostname,
		Port:     port,
		Path:     path,
		RawPath:  upstream.RawPath,
		RawQuery: upstream.RawQuery,
		Ip46:     ip46,
	}, nil
}

// Addresses refreshes hostnames through the daemon's TTL-aware resolver.
// Only literal addresses are fixed; diagnostic snapshots never drive dialing.
func (u *Upstream) Addresses(ctx context.Context) iter.Seq2[netip.Addr, error] {
	return func(yield func(netip.Addr, error) bool) {
		if u.Ip46 != nil {
			for _, ip := range []netip.Addr{u.Ip6, u.Ip4} {
				if ip.IsValid() && !yield(ip, ctx.Err()) {
					return
				}
			}
			return
		}
		ctx, cancel := context.WithTimeout(ctx, consts.DefaultDNSTimeout)
		defer cancel()
		var resolved []netip.Addr
		defer func() {
			u.mu.Lock()
			u.resolved = resolved
			u.mu.Unlock()
		}()
		for ip, err := range happyeyeballs.Resolve(ctx, net.DefaultResolver, "ip", u.Hostname) {
			if err == nil {
				resolved = append(resolved, ip)
			}
			if !yield(ip, err) {
				return
			}
		}
	}
}

func (u *Upstream) resolvedAddresses() []netip.Addr {
	if u.Ip46 != nil {
		return []netip.Addr{u.Ip6, u.Ip4}
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.resolved)
}

func (u *Upstream) Protocols() (l4protos []consts.L4ProtoStr) {
	switch u.Scheme {
	case UpstreamScheme_TCP, UpstreamScheme_HTTPS, UpstreamScheme_TLS:
		l4protos = []consts.L4ProtoStr{consts.L4ProtoStr_TCP}
	case UpstreamScheme_UDP, UpstreamScheme_QUIC, UpstreamScheme_H3:
		l4protos = []consts.L4ProtoStr{consts.L4ProtoStr_UDP}
	case UpstreamScheme_TCP_UDP:
		// UDP first.
		l4protos = []consts.L4ProtoStr{consts.L4ProtoStr_UDP, consts.L4ProtoStr_TCP}
	}
	return l4protos
}

func (u *Upstream) TransportName(protocol consts.L4ProtoStr) string {
	if u.Scheme == UpstreamScheme_TCP_UDP {
		return string(protocol)
	}
	return string(u.Scheme)
}

// Target preserves resolver identity for execution and pure cache diagnostics.
func (u *Upstream) Target(ip netip.Addr, protocol consts.L4ProtoStr) plugin.DNSUpstream {
	endpoint := (&url.URL{Scheme: u.TransportName(protocol), Host: net.JoinHostPort(u.Hostname, strconv.Itoa(int(u.Port))), Path: u.Path, RawPath: u.RawPath, RawQuery: u.RawQuery}).String()
	return plugin.DNSUpstream{Network: string(protocol), Address: netip.AddrPortFrom(ip, u.Port), Hostname: u.Hostname, Endpoint: endpoint}
}

func (u *Upstream) String() string {
	return string(u.Scheme) + "://" + net.JoinHostPort(u.Hostname, strconv.Itoa(int(u.Port))) + u.Path
}

type UpstreamResolver struct {
	Raw      *url.URL
	mu       sync.Mutex
	upstream *Upstream
}

func (u *UpstreamResolver) GetUpstream(ctx context.Context) (*Upstream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.upstream == nil {
		var err error
		u.upstream, err = NewUpstream(ctx, u.Raw)
		if err != nil {
			return nil, err
		}
	}
	return u.upstream, nil
}
