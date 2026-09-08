/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

// Startup sweeps can create four network operations per dialer at once.
const maxConcurrentCheckOperations = 128

var connectivityCheckSlots = make(chan struct{}, maxConcurrentCheckOperations)

type checkDNSOption struct {
	DnsPort uint16
	*netutils.Ip46
}

func parseCheckDNSOption(ctx context.Context, dnsHostPort []string) (*checkDNSOption, error) {
	if len(dnsHostPort) == 0 {
		return nil, fmt.Errorf("parseCheckDNSOption: bad format: empty")
	}

	host, rawPort, err := net.SplitHostPort(dnsHostPort[0])
	if err != nil {
		return nil, fmt.Errorf("parseCheckDNSOption: failed to split host and port: %w", err)
	}
	if host == "" {
		return nil, fmt.Errorf("parseCheckDNSOption: empty host")
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("bad port: %v", err)
	}
	if port == 0 {
		return nil, fmt.Errorf("bad port: 0")
	}
	var ip46 *netutils.Ip46
	if len(dnsHostPort) > 1 {
		ip46 = new(netutils.Ip46)
		for _, raw := range dnsHostPort[1:] {
			addr, err := netip.ParseAddr(raw)
			if err != nil {
				return nil, fmt.Errorf("parseCheckDNSOption: invalid IP address: %w", err)
			}
			if addr.Is4() || addr.Is4In6() {
				ip46.Ip4 = addr
			} else if addr.Is6() {
				ip46.Ip6 = addr
			}
			if ip46.Ip4.IsValid() && ip46.Ip6.IsValid() {
				break
			}
		}
	} else {
		ip46, err = netutils.ParseOrResolveIp46Context(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("parseCheckDNSOption: failed to resolve ip for %v: %w", host, err)
		}
		if !ip46.IsValid() {
			return nil, fmt.Errorf("ResolveIp46: no valid ip for %v", host)
		}
	}
	return &checkDNSOption{DnsPort: uint16(port), Ip46: ip46}, nil
}

type CheckDnsOptionRaw struct {
	opt *checkDNSOption
	mu  sync.Mutex
	Raw []string
}

func (c *CheckDnsOptionRaw) Option(ctx context.Context) (*checkDNSOption, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.opt == nil {
		opt, err := parseCheckDNSOption(ctx, c.Raw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse udp_check_dns: %w", err)
		}
		c.opt = opt
	}
	return c.opt, nil
}

func (d *Dialer) checkDNSConnectivity(ctx context.Context, networkType *common.NetworkType) (bool, error) {
	opt, err := d.CheckDnsOptionRaw.Option(ctx)
	if err != nil {
		return false, err
	}

	var ip netip.Addr
	switch networkType.IpVersion {
	case consts.IpVersionStr_4:
		ip = opt.Ip4
	case consts.IpVersionStr_6:
		ip = opt.Ip6
	}
	if !ip.IsValid() {
		log.WithFields(log.Fields{
			"resolver": d.CheckDnsOptionRaw.Raw[0],
			"node":     d.Name,
			"network":  networkType.String(),
		}).Trace("Skipping connectivity check: resolver has no address for this IP family")
		return false, nil
	}
	return d.dnsCheck(ctx, netip.AddrPortFrom(ip, opt.DnsPort), string(networkType.L4Proto))
}

type probeResult struct {
	network common.NetworkIndex
	latency time.Duration
	err     error
}

type checkResult struct {
	kind       checkKind
	generation uint64
	seq        uint64
	readiness  uint64
	connectErr error
	probes     []probeResult
}

// Failures can arise while establishing a session or while opening a probe
// through a stateless protocol (for example an HTTP CONNECT 407).
func (r checkResult) failure() error {
	causes := []error{r.connectErr}
	for _, probe := range r.probes {
		if probe.err != nil && !errors.Is(probe.err, netproxy.UnsupportedTunnelTypeError) {
			causes = append(causes, probe.err)
		}
	}
	return errors.Join(causes...)
}

func (c *connectivityChecker) performAttempt(ctx context.Context, attempt checkAttempt) checkResult {
	result := checkResult{
		kind:       attempt.kind,
		generation: attempt.generation,
	}
	snapshot, err := c.connectFor(ctx, attempt.kind == checkCapacity)
	result.seq = snapshot.Seq
	result.readiness = snapshot.ReadinessVersion
	if err != nil {
		result.connectErr = err
		return result
	}
	if attempt.kind == checkCapacity {
		return result
	}
	if !c.d.checksConnectivity {
		return result
	}

	states := c.d.networkStates()
	switch attempt.kind {
	case checkInitial:
		result.probes = c.probeMany(ctx, states, networkUntested, 1)
	case checkSupport:
		result.probes = c.probeMany(ctx, states, networkUnknown, 1)
	case checkHealth:
		first := firstSupportedNetwork(states)
		if !first.Valid() {
			return result
		}
		firstResult := c.probeNetwork(ctx, first, 2)
		result.probes = append(result.probes, firstResult)
	}
	return result
}

func (c *connectivityChecker) connectFor(ctx context.Context, replenish bool) (netproxy.StateEvent, error) {
	if c.d.session == nil {
		return netproxy.StateEvent{}, nil
	}
	snapshot := c.d.session.Snapshot()
	if !snapshot.Accepting || replenish {
		action := "connect"
		if replenish {
			action = "replenish"
		}
		c.d.updateRecovery(RecoveryQueued, time.Time{}, "connectivity_slot", action)
		if err := acquireConnectivityCheckSlot(ctx); err != nil {
			return snapshot, err
		}
		defer releaseConnectivityCheckSlot()
		c.d.startConnection(snapshot, action)
		if err := c.d.session.Connect(ctx); err != nil {
			return c.d.session.Snapshot(), err
		}
	}
	snapshot = c.d.session.Snapshot()
	if !snapshot.Accepting {
		return snapshot, netproxy.ErrNotConnected
	}
	return snapshot, nil
}

func (c *connectivityChecker) probeMany(ctx context.Context, states [common.NetworkTypeCount]networkState, wanted networkState, attempts int) []probeResult {
	results := make([]probeResult, 0, common.NetworkTypeCount)
	for _, network := range canonicalNetworkOrder {
		if states[network] == wanted {
			results = append(results, probeResult{network: network})
		}
	}
	var wg sync.WaitGroup
	for i := range results {
		network := results[i].network
		wg.Go(func() {
			results[i] = c.probeNetwork(ctx, network, attempts)
		})
	}
	wg.Wait()
	return results
}

func (c *connectivityChecker) probeNetwork(ctx context.Context, network common.NetworkIndex, attempts int) probeResult {
	first := c.runProbe(ctx, network)
	if first.err == nil || attempts == 1 || ctx.Err() != nil || recoveryBlockedReason(first.err) != "" {
		return first
	}
	retry := c.runProbe(ctx, network)
	if retry.err == nil {
		return retry
	}
	return first
}

func (c *connectivityChecker) runProbe(ctx context.Context, network common.NetworkIndex) probeResult {
	c.d.probeQueued()
	if err := acquireConnectivityCheckSlot(ctx); err != nil {
		return probeResult{network: network, err: err}
	}
	defer releaseConnectivityCheckSlot()
	c.d.probeStarted()
	defer c.d.probeFinished()
	start := time.Now()
	ok, err := c.probe(ctx, network.NetworkType())
	if ok {
		return probeResult{network: network, latency: time.Since(start)}
	}
	if err == nil {
		err = fmt.Errorf("check func not working")
	} else if strings.HasSuffix(err.Error(), "network is unreachable") {
		err = fmt.Errorf("network is unreachable")
	}
	return probeResult{network: network, err: err}
}

func acquireConnectivityCheckSlot(ctx context.Context) error {
	select {
	case connectivityCheckSlots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func releaseConnectivityCheckSlot() {
	<-connectivityCheckSlots
}

func (d *Dialer) dnsCheck(ctx context.Context, dns netip.AddrPort, network string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, consts.DefaultDialTimeout)
	defer cancel()
	addrs, err := netutils.ResolveNetipContext(ctx, d.Dialer, dns, consts.UdpCheckLookupHost, dnsmessage.TypeA, network)
	if err != nil {
		return false, err
	}
	if len(addrs) == 0 {
		return false, fmt.Errorf("bad DNS response: no record")
	}
	return true, nil
}
