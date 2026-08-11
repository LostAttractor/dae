/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/samber/oops"
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
	return scheme, hostname, port, __path, nil
}

type Upstream struct {
	Scheme   UpstreamScheme
	Hostname string
	Port     uint16
	Path     string
	*netutils.Ip46
}

// TODO: Sync with outbound
func NewUpstream(ctx context.Context, upstream *url.URL) (up *Upstream, err error) {
	scheme, hostname, port, path, err := ParseRawUpstream(upstream)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}

	ip46, err := netutils.ParseOrResolveIp46Context(ctx, hostname)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to resolve dns_upstream %v", upstream.String())
	}
	if !ip46.IsValid() {
		return nil, oops.Errorf("dns_upstream %v has no record", upstream.String())
	}

	return &Upstream{
		Scheme:   scheme,
		Hostname: hostname,
		Port:     port,
		Path:     path,
		Ip46:     ip46,
	}, nil
}

func (u *Upstream) SupportedNetworks() (ipversions []consts.IpVersionStr, l4protos []consts.L4ProtoStr) {
	if u.Ip4.IsValid() {
		ipversions = append(ipversions, consts.IpVersionStr_4)
	}
	if u.Ip6.IsValid() {
		ipversions = append(ipversions, consts.IpVersionStr_6)
	}
	switch u.Scheme {
	case UpstreamScheme_TCP, UpstreamScheme_HTTPS, UpstreamScheme_TLS:
		l4protos = []consts.L4ProtoStr{consts.L4ProtoStr_TCP}
	case UpstreamScheme_UDP, UpstreamScheme_QUIC, UpstreamScheme_H3:
		l4protos = []consts.L4ProtoStr{consts.L4ProtoStr_UDP}
	case UpstreamScheme_TCP_UDP:
		// UDP first.
		l4protos = []consts.L4ProtoStr{consts.L4ProtoStr_UDP, consts.L4ProtoStr_TCP}
	}
	return ipversions, l4protos
}

func (u *Upstream) String() string {
	return string(u.Scheme) + "://" + net.JoinHostPort(u.Hostname, strconv.Itoa(int(u.Port))) + u.Path
}

type UpstreamResolver struct {
	Raw *url.URL
	// FinishInitCallback may be invoked again if err is not nil
	FinishInitCallback func(upstream *Upstream)
	mu                 sync.Mutex
	upstream           *Upstream
}

func (u *UpstreamResolver) GetUpstream(ctx context.Context) (_ *Upstream, err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.upstream == nil {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		upstream, err := NewUpstream(ctx, u.Raw)
		if err != nil {
			return nil, fmt.Errorf("failed to init dns upstream: %w", err)
		}
		if u.FinishInitCallback != nil {
			u.FinishInitCallback(upstream)
		}
		u.upstream = upstream
	}
	return u.upstream, nil
}
