// SPDX-License-Identifier: AGPL-3.0-only

package surgemodule

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/daeuniverse/dae/component/routing"
)

func parseHost(line string, m *Module) error {
	key, value, ok := strings.Cut(line, "=")
	if !ok {
		return fmt.Errorf("Host mapping requires IP=IP[,IP...]")
	}
	source, err := netip.ParseAddr(strings.TrimSpace(key))
	if err != nil || source.Zone() != "" {
		appendModuleWarning(&m.Warnings, "Host supports only literal IP-to-IP mappings; domain, wildcard and ruleset entries are ignored")
		return nil
	}
	mapping := routing.DestinationRewrite{From: source.Unmap()}
	for _, target := range strings.Split(value, ",") {
		ip, err := netip.ParseAddr(strings.TrimSpace(target))
		if err != nil || ip.Zone() != "" {
			return fmt.Errorf("Host %s: expected a literal target IP, got %q", source, strings.TrimSpace(target))
		}
		mapping.To = append(mapping.To, ip.Unmap())
	}
	m.Hosts = append(m.Hosts, mapping)
	return nil
}

// DestinationRewrites exports Host entries in module/profile order. The
// forwarding layer owns policy gating, address selection and reply translation.
func (e *Engine) DestinationRewrites() routing.DestinationRewrites {
	var rules routing.DestinationRewrites
	for _, module := range e.options.Modules {
		rules = append(rules, module.Hosts...)
	}
	return rules
}
