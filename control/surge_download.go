// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/mitm"
	dnsmessage "github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

func newMITMClient(c *ControlPlane, timeout time.Duration) (*http.Client, func()) {
	lifetime, cancel := context.WithCancel(context.Background())
	var dials sync.RWMutex
	dial := mitmClientDialContext(c)
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				dials.RLock()
				defer dials.RUnlock()
				if lifetime.Err() != nil {
					return nil, net.ErrClosed
				}
				ctx, cancelDial := context.WithCancel(ctx)
				stop := context.AfterFunc(lifetime, cancelDial)
				defer func() {
					stop()
					cancelDial()
				}()
				return dial(ctx, network, address)
			},
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: timeout,
		},
		Timeout: timeout,
	}
	return client, func() {
		cancel()
		client.CloseIdleConnections()
		// Transport may outlive a canceled request. Join its dials before the
		// constructor replaces the DNS controller and routing matcher.
		dials.Lock()
		dials.Unlock()
	}
}

// Downloads originate in the daemon, before any client socket exists. Match
// its process name and an unspecified source, never a fabricated LAN device.
func mitmClientDialContext(c *ControlPlane) mitm.DialContext {
	processName, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		processName = []byte(filepath.Base(os.Args[0]))
	}
	process := bpfRoutingResult{Pid: uint32(os.Getpid())}
	copy(process.Pname[:], strings.TrimSpace(string(processName)))
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("mitm client: unsupported network %q", network)
		}
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("mitm client: invalid destination port %q", portText)
		}
		literal, _ := netip.ParseAddr(host)
		literal = literal.Unmap()
		domain := strings.TrimSuffix(host, ".")
		queryTypes := []uint16{dnsmessage.TypeA, dnsmessage.TypeAAAA}
		if c.dnsController != nil && c.dnsController.qtypePrefer == dnsmessage.TypeAAAA {
			queryTypes[0], queryTypes[1] = queryTypes[1], queryTypes[0]
		}
		switch {
		case literal.IsValid():
			domain, queryTypes = "", []uint16{0}
		case network == "tcp4":
			queryTypes = []uint16{dnsmessage.TypeA}
		case network == "tcp6":
			queryTypes = []uint16{dnsmessage.TypeAAAA}
		}
		var failures []error
		for _, qtype := range queryTypes {
			addresses := []netip.Addr{literal}
			if qtype != 0 {
				addresses, err = c.resolveMITMClient(ctx, domain, qtype, process)
				if err != nil {
					failures = append(failures, err)
					continue
				}
			}
			for _, ip := range addresses {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if (network == "tcp4" && !ip.Is4()) || (network == "tcp6" && !ip.Is6()) {
					failures = append(failures, fmt.Errorf("address %s does not match %s", ip, network))
					continue
				}
				routingResult := process
				param := &RouteParam{
					routingResult: &routingResult,
					networkType: common.NetworkType{
						L4Proto:   consts.L4ProtoStr_TCP,
						IpVersion: consts.IpVersionFromAddr(ip).ToIpVersionStr(),
					},
					Domain: domain,
					Src:    mitmClientSource(ip),
					Dest:   netip.AddrPortFrom(ip, uint16(port)),
				}
				outboundIndex, mark, _, err := c.Route(param.Src, param.Dest, domain, consts.L4ProtoType_TCP, &routingResult)
				if err != nil {
					return nil, err
				}
				option, err := c.selectDialOption(param, outboundIndex, mark, c.dialTargetOverride && domain != "")
				if err != nil {
					failures = append(failures, err)
					continue
				}
				entry := log.WithFields(log.Fields{
					"event": "download_dial", "outbound": option.Outbound.Name,
					"dialer": option.Dialer.Name, "destination": option.DialTarget,
					"destination_ip": ip.String(), "domain": domain,
				})
				if option.OriginalOutbound != nil {
					entry = entry.WithField("original_outbound", option.OriginalOutbound.Name)
				}
				if policy := option.Outbound.DisplayPolicy(); policy != "" {
					entry = entry.WithField("policy", policy)
				}
				if option.Outbound.Name == consts.OutboundBlock.String() {
					entry.WithField("action", "block").Info("mitm")
					return nil, fmt.Errorf("mitm client %s blocked by routing", address)
				}
				attemptCtx, cancel := context.WithTimeout(ctx, consts.DefaultDialTimeout)
				conn, err := option.dialerForConnection().DialContext(attemptCtx, "tcp", option.DialTarget)
				cancel()
				if err == nil {
					entry.Info("mitm")
					return conn, nil
				}
				entry.WithError(err).Debug("mitm")
				failures = append(failures, fmt.Errorf("outbound %q dialer %q: %w", option.Outbound.Name, option.Dialer.Name, err))
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("mitm client %s: %w", address, errors.Join(failures...))
	}
}

func mitmClientSource(destination netip.Addr) netip.AddrPort {
	if destination.Is4() {
		return netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
	}
	return netip.AddrPortFrom(netip.IPv6Unspecified(), 0)
}

// Resolve through dae's DNS request/response rules; asis uses fallback_resolver
// because these daemon requests have no intercepted DNS destination.
func (c *ControlPlane) resolveMITMClient(parent context.Context, host string, qtype uint16, process bpfRoutingResult) ([]netip.Addr, error) {
	dns := c.dnsController
	if dns == nil || !dns.admitDNSRequest() {
		return nil, net.ErrClosed
	}
	defer dns.activeRequests.Done()
	ctx, cancel := context.WithTimeout(parent, consts.DefaultDNSTimeout)
	defer cancel()
	stop := context.AfterFunc(dns.closed, cancel)
	defer stop()
	target, err := netip.ParseAddrPort(c.fallbackResolver)
	if err != nil {
		return nil, fmt.Errorf("mitm DNS fallback_resolver: %w", err)
	}
	message := new(dnsmessage.Msg)
	message.SetQuestion(dnsmessage.Fqdn(host), qtype)
	request := &udpRequest{src: mitmClientSource(target.Addr()), dst: target, routingResult: &process}
	query := dns.prepareQueryInfo(message)
	if err := dns.handleDNSRequest(ctx, message, request, query); err != nil {
		return nil, fmt.Errorf("resolve %s %s: %w", host, dnsmessage.TypeToString[qtype], err)
	}
	plan := dns.planDNSResponse(query, message.Answer)
	if message.Response && message.Rcode == dnsmessage.RcodeSuccess && plan != nil && len(plan.views) > 0 && len(plan.views[0].addresses) > 0 {
		return plan.views[0].addresses, nil
	}
	return nil, fmt.Errorf("resolve %s: no %s addresses (rcode %s)", host, dnsmessage.TypeToString[qtype], dnsmessage.RcodeToString[message.Rcode])
}
