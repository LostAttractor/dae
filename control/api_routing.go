// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"syscall"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"golang.org/x/sys/unix"
)

func (p *preparedRules) bypassLocalAPI(listen string) error {
	address, port, lan, err := config.ParseAPIEndpoint(listen)
	if err != nil || port == 0 {
		return err
	}
	p.apiScoped = lan
	var ip netip.Addr
	if !lan {
		ip = netip.MustParseAddrPort(address).Addr().Unmap()
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return fmt.Errorf("read host addresses for API routing: %w", err)
	}
	if ip.IsValid() && !ip.IsUnspecified() {
		addresses = slices.DeleteFunc(addresses, func(a net.Addr) bool {
			prefix, err := netip.ParsePrefix(a.String())
			return err != nil || prefix.Addr().Unmap() != ip
		})
	} else {
		ipv4, ipv6, err := apiListenFamilies(address)
		if err != nil {
			return fmt.Errorf("read API listen address families: %w", err)
		}
		addresses = slices.DeleteFunc(addresses, func(a net.Addr) bool {
			prefix, err := netip.ParsePrefix(a.String())
			return err != nil || prefix.Addr().Unmap().Is4() && !ipv4 || prefix.Addr().Unmap().Is6() && !ipv6
		})
	}
	p.bypassAPI(port, addresses)
	return nil
}

// Go's tcp wildcard (including 0.0.0.0) may select a dual-stack IPv6 socket.
// Inspect its chosen socket after default options, then abort before binding.
func apiListenFamilies(address string) (ipv4, ipv6 bool, err error) {
	inspected := errors.New("API listen socket inspected")
	lc := net.ListenConfig{Control: func(network, _ string, raw syscall.RawConn) error {
		ipv4, ipv6 = network == "tcp4", network == "tcp6"
		if ipv6 {
			var optionErr error
			if err := raw.Control(func(fd uintptr) {
				var only int
				only, optionErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY)
				ipv4 = only == 0
			}); err != nil {
				return err
			}
			if optionErr != nil {
				return optionErr
			}
		}
		return inspected
	}}
	_, err = lc.Listen(context.Background(), "tcp", address)
	if errors.Is(err, inspected) {
		err = nil
	}
	return ipv4, ipv6, err
}

// APIAddressChanges coalesces host address changes for serialized daemon publication.
func (c *ControlPlane) APIAddressChanges() <-chan struct{} {
	return c.core.apiAddressChanges
}

// APIRoutingCurrent compares the endpoint's exact address set with its bypass.
func (c *ControlPlane) APIRoutingCurrent() (bool, error) {
	var current preparedRules
	if err := current.bypassLocalAPI(c.apiListen); err != nil {
		return false, err
	}
	return c.matchesAPIBypass(current.apiBypass), nil
}

// RefreshAPIRouting atomically replaces the shared bypass/exemption address set.
// The daemon serializes it with configuration changes; no generation is retired.
func (c *ControlPlane) RefreshAPIRouting(ctx context.Context) error {
	c.core.lifecycleMu.Lock()
	defer c.core.lifecycleMu.Unlock()
	if c.closedDone.Load() {
		return net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var current preparedRules
	if err := current.bypassLocalAPI(c.apiListen); err != nil {
		return err
	}
	return c.replaceAPIAddresses(current.apiBypass)
}

func (c *ControlPlane) replaceAPIAddresses(addresses []netip.AddrPort) error {
	if c.matchesAPIBypass(addresses) {
		return nil
	}
	if c.routingState.apiSetSlot == nil {
		return fmt.Errorf("API address set is not installed")
	}
	if err := c.routingState.replacePrefixes(int(*c.routingState.apiSetSlot), apiBypassPrefixes(addresses), c.kernelReady); err != nil {
		return fmt.Errorf("refresh API address set: %w", err)
	}
	c.apiBypass = addresses
	return nil
}

func (c *ControlPlane) matchesAPIBypass(current []netip.AddrPort) bool {
	// Interface order and duplicate addresses do not change the exact
	// address/port set installed in the kernel.
	seen := make(map[netip.AddrPort]bool, len(current))
	for _, key := range current {
		seen[key] = false
	}
	for _, key := range c.apiBypass {
		if _, exists := seen[key]; !exists {
			return false
		}
		seen[key] = true
	}
	for _, exists := range seen {
		if !exists {
			return false
		}
	}
	return true
}

// Preserve the original LAN peer for the daemon's HTTP API. Only exact host
// addresses and this TCP port bypass routing, never their surrounding subnets.
func (p *preparedRules) bypassAPI(port uint16, addresses []net.Addr) {
	p.apiPort, p.apiBypass = port, nil
	if port == 0 {
		return
	}
	seen := make(map[netip.Addr]bool)
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil {
			continue
		}
		ip := prefix.Addr().Unmap()
		if (!ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast() && !ip.IsLoopback()) || seen[ip] {
			continue
		}
		p.apiBypass = append(p.apiBypass, netip.AddrPortFrom(ip, port))
		seen[ip] = true
	}
}

func apiBypassPrefixes(addresses []netip.AddrPort) []netip.Prefix {
	prefixes := make([]netip.Prefix, len(addresses))
	for i, address := range addresses {
		ip := address.Addr()
		prefixes[i] = netip.PrefixFrom(ip, ip.BitLen())
	}
	slices.SortFunc(prefixes, netip.Prefix.Compare)
	return slices.Compact(prefixes)
}

func apiIngressKey(index uint32) (key [16]byte) {
	binary.BigEndian.PutUint32(key[12:], index)
	return key
}

// SetAPIInterfaces receives only sockets reserved by the listener for this generation.
func (c *ControlPlane) SetAPIInterfaces(indices []uint32) error {
	s := c.routingState
	if s == nil || s.apiIngressSlot == nil {
		return nil
	}
	prefixes := make([]netip.Prefix, 0, len(indices))
	for _, index := range indices {
		if index != 0 {
			prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom16(apiIngressKey(index)), 128))
		}
	}
	slices.SortFunc(prefixes, netip.Prefix.Compare)
	return s.replacePrefixes(int(*s.apiIngressSlot), prefixes, c.kernelReady)
}

func (b *RoutingMatcherBuilder) compileAPIBypass(p *preparedRules) {
	if p.apiPort == 0 {
		return
	}
	// A dedicated slot prevents live API addresses from mutating static dip rules.
	b.apiSetSlot = new(uint32(len(b.simulatedLpmTries)))
	b.simulatedLpmTries = append(b.simulatedLpmTries, apiBypassPrefixes(p.apiBypass))
	var slot [16]byte
	binary.LittleEndian.PutUint32(slot[:], *b.apiSetSlot)
	start := uint32(len(b.rules))
	b.rules = append(b.rules,
		bpfMatchSet{Type: uint8(consts.MatchType_IpSet), Action: uint8(consts.MatchActionAnd), Value: slot},
		bpfMatchSet{Type: uint8(consts.MatchType_Port), Action: uint8(consts.MatchActionAnd), Value: encodePortRange([2]uint16{p.apiPort, p.apiPort})},
	)
	// Describe the live set, not address literals that diagnostics would retain after a refresh.
	rule := &config_parser.RoutingRule{
		AndFunctions: []*config_parser.Function{
			{Name: "dip", Params: []*config_parser.Param{{Val: "<API addresses>"}}},
			{Name: "dport", Params: []*config_parser.Param{{Val: strconv.Itoa(int(p.apiPort))}}},
		},
		Outbound: config_parser.Function{Name: "direct"},
	}
	if p.apiScoped {
		b.apiIngressSlot = new(uint32(len(b.simulatedLpmTries)))
		b.simulatedLpmTries = append(b.simulatedLpmTries, nil)
		var value [16]byte
		binary.LittleEndian.PutUint32(value[:], *b.apiIngressSlot)
		b.rules = append(b.rules, bpfMatchSet{Type: uint8(consts.MatchType_APIIngress), Action: uint8(consts.MatchActionAnd), Value: value})
		rule.AndFunctions = append(rule.AndFunctions, &config_parser.Function{Name: "ifindex", Params: []*config_parser.Param{{Val: "<API interfaces>"}}})
	}
	b.rules = append(b.rules, bpfMatchSet{Type: uint8(consts.MatchType_L4Proto), Action: uint8(consts.MatchActionRoute), Flags: matchFlagBypass, Outbound: uint8(consts.OutboundDirect), Value: [16]byte{byte(consts.L4ProtoType_TCP)}})
	rule.AndFunctions = append(rule.AndFunctions, &config_parser.Function{Name: "l4proto", Params: []*config_parser.Param{{Val: "tcp"}}})
	for i, function := range rule.AndFunctions {
		b.rememberMatch(int(start)+i, function)
	}
	b.rememberRule(start, rule, "api_bypass", "routing")
}
