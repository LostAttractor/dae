// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

func TestDomainSnapshotRetainsVerificationAndInstalledState(t *testing.T) {
	g, fake := newTestRegistry(2, time.Minute)
	now := time.Now()
	ip := netip.MustParseAddr("192.0.2.1")
	other := netip.MustParseAddr("192.0.2.2")
	v6 := netip.MustParseAddr("2001:db8::1")
	g.Upsert("initial.example.", ip, testBitmap(0), 120, now)
	g.Upsert("outside.example.", other, testBitmap(), 120, now)
	g.Upsert("outside.example.", v6, testBitmap(), 120, now)
	g.kernel.update = func(netip.Addr, []uint32, []uint32) error { return errors.New("publication blocked") }
	g.Upsert("new.example.", ip, testBitmap(1), 120, now)
	generation := g.generation
	snapshot := g.Snapshot([]netip.Addr{netip.MustParseAddr("::ffff:192.0.2.1")}, "outside.example.")
	if g.generation != generation || len(g.kernel.pending) != 1 {
		t.Fatal("snapshot changed retention or projection")
	}
	for name, record := range snapshot.names {
		for address, pair := range record.pairs {
			if pair.verification != g.Verify(name, address) {
				t.Fatalf("snapshot/live differ for %s at %s", name, address)
			}
		}
	}
	if snapshot.names["outside.example."].families != [2]int{1, 1} || len(snapshot.names["outside.example."].pairs) != 2 {
		t.Fatal("name selection lost cross-family registration")
	}
	before := snapshot.names["new.example."].pairs[ip]
	if !before.resident || before.verification.KernelCovered || !slices.Equal(snapshot.kernel[ip].routing, testBitmap(0)) {
		t.Fatal("snapshot confused installed routing with current evidence")
	}
	g.kernel.update = fake.update
	g.retryProjection(now.Add(time.Second))
	if !g.Verify("new.example.", ip).KernelCovered || snapshot.names["new.example."].pairs[ip] != before || !slices.Equal(snapshot.kernel[ip].routing, testBitmap(0)) {
		t.Fatal("projection retry changed an earlier snapshot")
	}
	current := g.Snapshot([]netip.Addr{ip}, "")
	clear(current.kernel[ip].bump)
	bump, _ := g.kernelRoutingBitmaps(ip)
	if !slices.Equal(bump, testBitmap(0, 1)) {
		t.Fatal("snapshot bitmap aliases the live projection")
	}
	if record := current.names["outside.example."]; record.families != [2]int{1, 1} || len(record.pairs) != 0 {
		t.Fatal("filtered snapshot lost registration outside selected pairs")
	}
}

func TestDiagnosticsCoverageMatchesVerifyDuringProjectionRetry(t *testing.T) {
	for _, relevant := range []bool{false, true} {
		t.Run(map[bool]string{false: "zero-bit domain", true: "routing domain"}[relevant], func(t *testing.T) {
			rules := "domain(full: initial.example) -> proxy"
			if relevant {
				rules += "\ndomain(full: target.example) -> block"
			}
			c := diagnosticPlane(t, rules, "")
			c.sniffVerifyMode = consts.SniffVerifyMode_Strict
			request := diagnosticRequest()
			request.Flow.SNI = new("target.example")
			matcher := c.routingMatcher.diagnosticSnapshot()
			input, _, _, err := diagnosticInput(request, matcher)
			if err != nil {
				t.Fatal(err)
			}
			g := c.core.domainRegistry
			now := time.Now()
			ip := input.dst.Addr()
			g.Upsert("initial.example.", ip, matcher.domainMatcher.MatchDomainBitmap("initial.example"), 120, now)
			update := g.kernel.update
			g.kernel.update = func(netip.Addr, []uint32, []uint32) error { return errors.New("publication blocked") }
			g.Upsert("target.example.", ip, matcher.domainMatcher.MatchDomainBitmap("target.example"), 120, now)
			for _, retry := range []bool{false, true} {
				if retry {
					g.kernel.update = update
					g.retryProjection(now.Add(time.Second))
				}
				state, err := c.diagnosticState(request, input, matcher)
				if err != nil {
					t.Fatal(err)
				}
				verified, reroute, err := c.verifySniff(t.Context(), input.dst, "target.example")
				if err != nil || !verified || reroute == retry {
					t.Fatalf("live verification: verified=%v reroute=%v err=%v", verified, reroute, err)
				}
				facts := routeFacts{outbound: consts.OutboundUserDefinedMin, mode: consts.RerouteMode_WhileNeed}
				got, known, missing := c.diagnosticRoutePlan(request, state, input.dst, "target.example", false, nil, facts)
				facts.verified, facts.shouldReroute = routingTruth(verified), routingTruth(reroute)
				if want := planRoute(facts); got != want || !known || len(missing) != 0 {
					t.Fatalf("diagnostic=%+v live=%+v missing=%v", got, want, missing)
				}
			}
		})
	}
}
