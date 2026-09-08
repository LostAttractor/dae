// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"github.com/daeuniverse/dae/common/consts"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/component/network"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func testRoutingConfig(rules []*config_parser.RoutingRule, fallback config.FunctionOrString) *config.Routing {
	fallbackFunction, err := config.ParseFunctionOrString(fallback)
	if err != nil {
		panic(err) // Test fixture programming error.
	}
	statements := make([]config.RoutingStatement, 0, len(rules))
	for _, rule := range rules {
		statements = append(statements, config.RoutingStatement{Kind: config.RoutingStatementRule, Rule: rule})
	}
	return &config.Routing{Policies: []config.RoutingPolicy{{Statements: statements, Fallback: fallbackFunction}}}
}

// Tests use the same preparation and compilation path as a control plane.
func compileTestRouting(input preparedRules, outbounds map[string]uint8, bpf *BPFState, ifmgr *network.InterfaceManager) (*RoutingMatcherBuilder, error) {
	if input.routing == nil {
		input.routing = testRoutingConfig(nil, "direct")
	}
	conf, err := prepareRoutingConfig(input.routing, routing.NewDatReaderOptimizer(context.Background(), assets.NewLocationFinder(nil)))
	if err != nil {
		return nil, err
	}
	input.routing = conf
	return input.compileRouting(outbounds, bpf, ifmgr)
}

// Convert byte-oriented packet fixtures to the shared routing input.
func matchTestRouting(m *RoutingMatcher, source, dest []byte, sport, dport uint16, _ consts.IpVersionType, proto consts.L4ProtoType, domain string, pname [16]byte, ifindex uint32, dscp uint8, mac []byte, bitmaps ...[]uint32) (consts.OutboundIndex, uint32, bool, error) {
	p := routingInput{src: netip.AddrPortFrom(netip.AddrFrom16(*(*[16]byte)(source)).Unmap(), sport), dst: netip.AddrPortFrom(netip.AddrFrom16(*(*[16]byte)(dest)).Unmap(), dport), l4proto: proto, domain: domain, processName: pname, ifindex: ifindex, dscp: dscp, mac: *(*[6]byte)(mac[10:])}
	if len(bitmaps) > 0 {
		p.domainBitmap = bitmaps[0]
	}
	if len(bitmaps) > 1 {
		p.domainBumpBitmap = bitmaps[1]
		p.kernel = true
	}
	return m.match(p)
}

func planRulesForTest(t *testing.T, text string) []*config_parser.RoutingRule {
	t.Helper()
	conf := prepareFlowRulesForTest(t, "", text).routing
	var rules []*config_parser.RoutingRule
	for _, statement := range conf.Policies[0].Statements {
		rules = append(rules, statement.Rule)
	}
	return rules
}
