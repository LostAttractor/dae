// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/component/mitm/plugin"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// API bypass rules must terminate before either HTTP or destination capture.
// Capture must retain host and port constraints: unrelated direct traffic must
// stay in eBPF even when plugins are enabled. Missing DNS evidence is not a
// reason to divert all TCP or UDP to userspace.
type routingCapture struct {
	before         int
	http           []plugin.Scope
	requestRouting []plugin.Scope
	controls       []routing.FlowRule
}

// Group positive hosts by their port set, preserving each host/port pairing.
// DNS supplies domain candidates; literal IP scopes need no DNS registration.
// Shared IPs and ordered exclusions are checked again against the actual host
// in userspace. An exclusion in one scope must not erase another scope's allow.
func mitmCapturePredicates(scopes []plugin.Scope) [][]*config_parser.Function {
	type hostGroup struct {
		ports   []uint16
		domains []*config_parser.Param
		ips     []*config_parser.Param
		seen    map[string]bool
	}
	var groups []*hostGroup
	byPorts := make(map[string]*hostGroup)
	for _, scope := range scopes {
		for _, rule := range scope {
			host := strings.TrimSuffix(strings.ToLower(rule.Host), ".")
			if rule.Exclude || host == "" {
				continue
			}
			ports := slices.DeleteFunc(slices.Clone(rule.Ports), func(port uint16) bool { return port == 0 })
			slices.Sort(ports)
			ports = slices.Compact(ports)
			if len(rule.Ports) != 0 && len(ports) == 0 {
				continue // Port zero never matches; do not turn it into all ports.
			}
			key := fmt.Sprint(ports)
			group := byPorts[key]
			if group == nil {
				group = &hostGroup{ports: ports, seen: make(map[string]bool)}
				byPorts[key] = group
				groups = append(groups, group)
			}
			if ip, err := netip.ParseAddr(host); err == nil {
				host = ip.Unmap().String()
				if !group.seen[host] {
					group.ips = append(group.ips, &config_parser.Param{Val: host})
				}
			} else if !group.seen[host] {
				param := &config_parser.Param{Key: "full", Val: host}
				if strings.ContainsAny(host, "*?") {
					pattern := regexp.QuoteMeta(host)
					pattern = strings.ReplaceAll(strings.ReplaceAll(pattern, `\*`, ".*"), `\?`, ".")
					param.Key, param.Val = "regex", "^"+pattern+"$"
				}
				group.domains = append(group.domains, param)
			}
			group.seen[host] = true
		}
	}
	var predicates [][]*config_parser.Function
	for _, group := range groups {
		for _, hosts := range []*config_parser.Function{{Name: "domain", Params: group.domains}, {Name: "dip", Params: group.ips}} {
			if len(hosts.Params) == 0 {
				continue
			}
			predicate := []*config_parser.Function{
				{Name: "l4proto", Params: []*config_parser.Param{{Val: "tcp"}, {Val: "udp"}}}, hosts,
			}
			if len(group.ports) != 0 {
				ports := &config_parser.Function{Name: "dport"}
				for _, port := range group.ports {
					ports.Params = append(ports.Params, &config_parser.Param{Val: strconv.Itoa(int(port))})
				}
				predicate = append(predicate, ports)
			}
			predicates = append(predicates, predicate)
		}
	}
	return predicates
}
