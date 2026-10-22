// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"net/netip"
	"slices"
	"testing"
)

type recordingUpstreamCache struct {
	answer   *DNSResponse
	outcomes []bool
}

func (*recordingUpstreamCache) Plan() Plan { return Plan{} }
func (c *recordingUpstreamCache) LookupDNSUpstream(*DNSExchange) *DNSResponse {
	return c.answer
}
func (c *recordingUpstreamCache) RecordDNSUpstream(_ *DNSExchange, hit bool) {
	c.outcomes = append(c.outcomes, hit)
}
func (*recordingUpstreamCache) StoreDNSUpstream(_ *DNSExchange, response *DNSResponse) *DNSResponse {
	return response
}

// Each consulted cache records one outcome per upstream query, however many
// candidates looked it up: a hit in the answering cache, a miss in caches
// consulted before it, and nothing in caches after it.
func TestUpstreamQueryRecordsOneOutcomePerCache(t *testing.T) {
	for _, test := range []struct {
		name     string
		answered []bool
		lookups  int
		want     [][]bool
	}{
		{name: "miss in every cache", answered: []bool{false, false}, lookups: 2, want: [][]bool{{false}, {false}}},
		{name: "hit in a later cache", answered: []bool{false, true}, lookups: 2, want: [][]bool{{false}, {true}}},
		{name: "hit in the first cache", answered: []bool{true, true}, lookups: 1, want: [][]bool{{true}, nil}},
		{name: "never looked up", answered: []bool{true, true}, want: [][]bool{nil, nil}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var caches []DNSUpstreamCache
			var recorders []*recordingUpstreamCache
			for _, answered := range test.answered {
				cache := new(recordingUpstreamCache)
				if answered {
					cache.answer = new(DNSResponse)
				}
				caches, recorders = append(caches, cache), append(recorders, cache)
			}
			query := (&DNSExchange{SelectCaches: func(DNSPacket) []DNSUpstreamCache { return caches }}).UpstreamQuery()
			delivered := new(DNSResponse) // A network answer unless a cache replays one.
			for range test.lookups {
				prepared, err := query.Prepare(t.Context(), DNSUpstream{Network: "udp", Address: netip.MustParseAddrPort("192.0.2.53:53")})
				if err != nil {
					t.Fatal(err)
				}
				if response := prepared.Lookup(); response != nil {
					delivered = response
				}
			}
			query.Finish(delivered)
			for i, cache := range recorders {
				if !slices.Equal(cache.outcomes, test.want[i]) {
					t.Fatalf("cache %d recorded %v, want %v", i, cache.outcomes, test.want[i])
				}
			}
		})
	}
}
