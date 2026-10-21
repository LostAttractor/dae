// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/internal/pluginctx"
	"github.com/daeuniverse/dae/pkg/outbound/happyeyeballs"
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
// Each candidate has its own pool key; requests and downloads consume candidates
// lazily and stop after a successful dial. A block terminates the stream.
func (c *ControlPlane) httpRouteCandidates(ctx context.Context, network string, target httpTarget, source netip.AddrPort, identity routingResult) iter.Seq2[*DialOption, error] {
	return func(yield func(*DialOption, error) bool) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" && network != "udp" {
			yield(nil, fmt.Errorf("unsupported HTTP network %q", network))
			return
		}
		ctx, cancel := context.WithTimeout(ctx, consts.DefaultDNSTimeout)
		defer cancel()
		if c.ctx != nil {
			stop := context.AfterFunc(c.ctx, cancel)
			defer stop()
		}
		family := "ip"
		if network == "tcp4" || network == "tcp6" {
			family += network[3:]
		}
		domain := target.host
		if _, err := netip.ParseAddr(domain); err == nil {
			domain = ""
		}
		var failures []error
		yielded := false
		for ip, err := range happyeyeballs.Resolve(ctx, net.DefaultResolver, family, target.host) {
			if err != nil {
				yield(nil, err)
				return
			}
			option, err := c.selectHTTPAddress(ctx, network, source, identity, domain, netip.AddrPortFrom(ip, target.port))
			if err != nil {
				failures = append(failures, err)
				continue
			}
			if option.Outbound.IsBlock() {
				yield(nil, fmt.Errorf("HTTP upstream blocked by routing"))
				return
			}
			yielded = true
			if !yield(option, nil) {
				return
			}
		}
		if !yielded {
			yield(nil, errors.Join(failures...))
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
