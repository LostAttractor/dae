// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"

	"github.com/daeuniverse/dae/component/mitm/plugin"
)

// Keep Surge's ordered exclusions, :0 wildcard and HTTP-port exception inside
// the compatibility layer. Native plugins use explicit host/port rules.
func moduleScope(hostnames []string) (plugin.Scope, error) {
	var scope plugin.Scope
	for _, pattern := range hostnames {
		rule := plugin.HostRule{Exclude: strings.HasPrefix(pattern, "-"), Ports: []uint16{80, 443}}
		rule.Host = strings.TrimPrefix(pattern, "-")
		if host, port, err := net.SplitHostPort(rule.Host); err == nil {
			n, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid MITM port in %q", pattern)
			}
			rule.Host = host
			if n == 0 {
				rule.Ports = nil
			} else {
				rule.Ports = []uint16{80, uint16(n)}
			}
		}
		host := strings.TrimSuffix(rule.Host, ".")
		_, ipErr := netip.ParseAddr(host)
		if host == "" || strings.HasPrefix(host, "-") ||
			strings.ContainsAny(host, "/\\[]@#%<>") ||
			strings.ContainsFunc(host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) ||
			(strings.Contains(host, ":") && ipErr != nil) {
			return nil, fmt.Errorf("invalid MITM hostname %q", pattern)
		}
		scope = append(scope, rule)
	}
	return scope, nil
}
