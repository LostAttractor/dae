// SPDX-License-Identifier: AGPL-3.0-only

package surgemodule

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func parseHost(line string, m *Module) error {
	key, value, ok := strings.Cut(line, "=")
	if !ok {
		return fmt.Errorf("Host mapping requires host=IP[,IP...]")
	}
	key, value = strings.TrimSpace(key), strings.TrimSpace(value)
	if key == "" || value == "" {
		return fmt.Errorf("Host requires a non-empty matcher and target")
	}
	var mapping routing.DestinationRewrite
	if source, err := netip.ParseAddr(key); err == nil && source.Zone() == "" {
		mapping.Filter = []*config_parser.Function{{Name: "dip", Params: []*config_parser.Param{{Val: source.Unmap().String()}}}}
	} else {
		if strings.ContainsAny(key, "/:\\= \t\r\n[]") {
			return fmt.Errorf("Host matcher %q is unsupported; expected an IP or hostname pattern", key)
		}
		key = strings.TrimSuffix(strings.ToLower(key), ".")
		kind, pattern := "full", key
		if strings.ContainsAny(key, "*?") {
			kind = "regex"
			pattern = "^" + strings.ReplaceAll(strings.ReplaceAll(regexp.QuoteMeta(key), `\*`, ".*"), `\?`, ".") + "$"
		}
		mapping.Filter = []*config_parser.Function{{Name: "domain", Params: []*config_parser.Param{{Key: kind, Val: pattern}}}}
	}
	if strings.HasPrefix(value, "server:") || strings.HasPrefix(value, "script:") {
		return fmt.Errorf("Host %s: DNS server assignment and DNS scripts are unsupported", key)
	}
	for _, target := range strings.Split(value, ",") {
		ip, err := netip.ParseAddr(strings.TrimSpace(target))
		if err != nil || ip.Zone() != "" {

			return fmt.Errorf("Host %s: expected a literal target IP, got %q", key, strings.TrimSpace(target))
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
