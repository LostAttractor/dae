// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"encoding/binary"
	"math"
	"net/netip"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	log "github.com/sirupsen/logrus"
)

// Capture is one kernel match set: destination IP OR (TCP AND domain).
// The API bypass may precede it; all ordinary routing follows it.
type routingCapture struct {
	before  int
	ips     []netip.Addr
	domains []string
}

func (b *RoutingMatcherBuilder) addCapture(capture *routingCapture) {
	b.captureIndex = len(b.rules)
	set := bpfMatchSet{Type: uint8(consts.MatchType_Capture), Outbound: uint8(consts.OutboundControlPlaneRouting)}
	// A domain-only capture needs no LPM map.
	index := uint32(math.MaxUint32)
	if len(capture.ips) != 0 {
		index = uint32(len(b.simulatedLpmTries))
		prefixes := make([]netip.Prefix, 0, len(capture.ips))
		for _, ip := range capture.ips {
			prefixes = append(prefixes, netip.PrefixFrom(ip, ip.BitLen()))
		}
		b.simulatedLpmTries = append(b.simulatedLpmTries, prefixes)
	}
	binary.LittleEndian.PutUint32(set.Value[:], index)
	if len(capture.domains) != 0 {
		set.Value[4] = 1 // match_set.capture.domains
		b.simulatedDomainSet = append(b.simulatedDomainSet, routing.DomainSet{
			Key: consts.RoutingDomainKey_Regex, RuleIndex: b.captureIndex, Domains: capture.domains,
		})
	}
	b.rules = append(b.rules, set)
	log.WithFields(log.Fields{"match_index": b.captureIndex, "ips": capture.ips, "domains": capture.domains}).Debug("Prepared control-plane capture")
}
