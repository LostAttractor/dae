// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"fmt"
	"iter"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/internal/pluginctx"
	dnsmessage "github.com/miekg/dns"
)

type httpTarget struct {
	host string
	port uint16
}

func (t httpTarget) String() string { return net.JoinHostPort(t.host, strconv.Itoa(int(t.port))) }

func parseHTTPTarget(address string) (httpTarget, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return httpTarget{}, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 || host == "" {
		return httpTarget{}, fmt.Errorf("invalid HTTP target %q", address)
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.Unmap().String()
	}
	return httpTarget{host: host, port: uint16(port)}, nil
}

func requestHTTPTarget(request *http.Request) (httpTarget, error) {
	if request.URL == nil || (request.URL.Scheme != "http" && request.URL.Scheme != "https") {
		return httpTarget{}, fmt.Errorf("unsupported HTTP target")
	}
	port := request.URL.Port()
	if port == "" {
		port = "80"
		if request.URL.Scheme == "https" {
			port = "443"
		}
	}
	return parseHTTPTarget(net.JoinHostPort(request.URL.Hostname(), port))
}

// One candidate stream serves intercepted requests and daemon downloads.
// Requests collect the plan before pool lookup; downloads consume it lazily
// and stop after a successful dial. A block always terminates the stream.
func (c *ControlPlane) httpRouteCandidates(ctx context.Context, network string, target httpTarget, source netip.AddrPort, identity routingResult) iter.Seq2[*DialOption, error] {
	return func(yield func(*DialOption, error) bool) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" && network != "udp" {
			yield(nil, fmt.Errorf("unsupported HTTP network %q", network))
			return
		}
		literal, _ := netip.ParseAddr(target.host)
		domain := target.host
		queryTypes := []uint16{dnsmessage.TypeA, dnsmessage.TypeAAAA}
		switch {
		case literal.IsValid():
			domain, queryTypes = "", []uint16{0}
		case network == "tcp4":
			queryTypes = []uint16{dnsmessage.TypeA}
		case network == "tcp6":
			queryTypes = []uint16{dnsmessage.TypeAAAA}
		}
		for _, qtype := range queryTypes {
			if err := ctx.Err(); err != nil {
				yield(nil, err)
				return
			}
			addresses := []netip.Addr{literal}
			if qtype != 0 {
				var err error
				addresses, err = c.resolveHTTPAddresses(ctx, domain, qtype, source, identity)
				if err != nil {
					if !yield(nil, err) {
						return
					}
					continue
				}
			}
			for _, ip := range addresses {
				if err := ctx.Err(); err != nil {
					yield(nil, err)
					return
				}
				ip = ip.Unmap()
				if (network == "tcp4" && !ip.Is4()) || (network == "tcp6" && !ip.Is6()) {
					if !yield(nil, fmt.Errorf("address %s does not match %s", ip, network)) {
						return
					}
					continue
				}
				option, err := c.selectHTTPAddress(ctx, network, source, identity, domain, netip.AddrPortFrom(ip, target.port))
				if !yield(option, err) || (err == nil && option.Outbound.Name == consts.OutboundBlock.String()) {
					return
				}
			}
		}
	}
}

func (c *ControlPlane) selectHTTPAddress(ctx context.Context, network string, source netip.AddrPort, identity routingResult, domain string, address netip.AddrPort) (*DialOption, error) {
	policy := pluginctx.HTTPPolicy(ctx)
	if policy == "" {
		return c.selectRoutedAddress(network, source, identity, domain, address)
	}
	switch strings.ToUpper(policy) {
	case "DIRECT":
		policy = consts.OutboundDirect.String()
	case "REJECT":
		policy = consts.OutboundBlock.String()
	}
	for index, group := range c.outbounds {
		if group.Name == policy {
			return c.selectAddress(network, source, identity, domain, address, new(consts.OutboundIndex(index)))
		}
	}
	return nil, fmt.Errorf("HTTP policy %q is not an active outbound", policy)
}

// Daemon-originated lookups use the internal resolver installed at startup.
// They do not depend on the availability or configuration of DNS plugins.
func (c *ControlPlane) resolveHTTPAddresses(parent context.Context, host string, qtype uint16, source netip.AddrPort, process routingResult) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(parent, consts.DefaultDNSTimeout)
	defer cancel()
	if c.ctx != nil {
		stop := context.AfterFunc(c.ctx, cancel)
		defer stop()
	}
	network := "ip4"
	if qtype == dnsmessage.TypeAAAA {
		network = "ip6"
	}
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}
