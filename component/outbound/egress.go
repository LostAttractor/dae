// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

const (
	family4 uint8 = 1 << iota
	family6
	allFamilies = family4 | family6
)

// EntryOptions belong to the first physical hop, rather than to path scoring.
// Nil Mark and Families inherit the global mark and allow both families.
type EntryOptions struct {
	Mark      *uint32
	Interface string
	Families  *uint8
}

func (e EntryOptions) configured() bool {
	return e.Mark != nil || e.Interface != "" || e.Families != nil
}

func parseStageAnnotations(params []*config_parser.Param) (*dialer.Annotation, EntryOptions, error) {
	var entry EntryOptions
	var scoring []*config_parser.Param
	seen := make(map[string]bool, len(params))
	for _, param := range params {
		if seen[param.Key] {
			return nil, entry, fmt.Errorf("duplicate path-stage annotation: %s", param.Key)
		}
		seen[param.Key] = true
		switch param.Key {
		case "mark":
			base := 10
			value := param.Val
			if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
				base, value = 16, value[2:]
			}
			mark, err := strconv.ParseUint(value, base, 32)
			if err != nil {
				return nil, entry, fmt.Errorf("invalid mark %q: %w", param.Val, err)
			}
			if err := common.ValidateSoMarkFromDae(uint32(mark)); err != nil {
				return nil, entry, err
			}
			entry.Mark = new(uint32(mark))
		case "interface":
			if param.Val == "" || len(param.Val) > 15 || strings.ContainsAny(param.Val, "\x00/: \t\r\n\v\f") || param.Val == "." || param.Val == ".." {
				return nil, entry, fmt.Errorf("invalid interface name %q", param.Val)
			}
			entry.Interface = param.Val
		default:
			scoring = append(scoring, param)
		}
	}
	annotation, err := dialer.NewAnnotation(scoring)
	return annotation, entry, err
}

// IP version filters describe the entrance transport, not original node
// properties. Defer their expansion until references and logical paths resolve.
func splitEntryFilters(filters []*config_parser.Function) ([]*config_parser.Function, *uint8, error) {
	var properties []*config_parser.Function
	var families *uint8
	for _, filter := range filters {
		if filter.Name != "ipversion" {
			properties = append(properties, filter)
			continue
		}
		if len(filter.Params) == 0 {
			return nil, nil, fmt.Errorf("ipversion requires 4 or 6")
		}
		var mask uint8
		for _, param := range filter.Params {
			if param.Key != "" || param.Val != "4" && param.Val != "6" {
				return nil, nil, fmt.Errorf("ipversion requires 4 or 6, got %q", param.String(false, true))
			}
			if param.Val == "4" {
				mask |= family4
			} else {
				mask |= family6
			}
		}
		if filter.Not {
			mask ^= allFamilies
		}
		if families == nil {
			families = new(uint8(allFamilies))
		}
		*families &= mask
	}
	return properties, families, nil
}

func mergeEntryOptions(inner, outer EntryOptions) (EntryOptions, error) {
	if outer.Mark != nil {
		if inner.Mark != nil && *inner.Mark != *outer.Mark {
			return EntryOptions{}, fmt.Errorf("conflicting entry mark annotations")
		}
		inner.Mark = outer.Mark
	}
	if outer.Interface != "" {
		if inner.Interface != "" && inner.Interface != outer.Interface {
			return EntryOptions{}, fmt.Errorf("conflicting entry interface annotations")
		}
		inner.Interface = outer.Interface
	}
	if outer.Families != nil {
		mask := *outer.Families
		if inner.Families != nil {
			mask &= *inner.Families
		}
		inner.Families = new(mask)
	}
	return inner, nil
}

func entryHostname(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		// Hysteria2 also accepts a hostname or bracketed IP without a port.
		host = strings.TrimSuffix(strings.TrimPrefix(address, "["), "]")
	}
	return host
}

func entryAddressFamilies(address string) uint8 {
	return entryHostFamilies(entryHostname(address))
}

func entryHostFamilies(host string) uint8 {
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Unmap().Is4() {
			return family4
		}
		return family6
	}
	return allFamilies
}
