// SPDX-License-Identifier: AGPL-3.0-only

package dnscache

import (
	"testing"

	dns "github.com/miekg/dns"
)

func TestEDNSRejectsMalformedEnvelope(t *testing.T) {
	for _, mutate := range []func(*dns.Msg){
		func(m *dns.Msg) { m.Extra = append(m.Extra, dns.Copy(m.Extra[0])) },
		func(m *dns.Msg) { m.IsEdns0().Hdr.Name = "not-root.example." },
		func(m *dns.Msg) { m.IsEdns0().SetVersion(1) },
	} {
		q, _ := cacheMessages()
		q.SetEdns0(1232, false)
		mutate(q)
		if _, ok := EDNS(q); ok {
			t.Fatal("accepted invalid OPT envelope")
		}
		if _, ok := QueryKey(q); ok {
			t.Fatal("keyed invalid OPT envelope")
		}
	}
}

func TestReplayReplacesControlDataButPreservesRecords(t *testing.T) {
	q, r := cacheMessages()
	r.Extra = append(r.Extra, dns.Copy(r.Answer[0]))
	r.SetEdns0(4096, true)
	q.SetEdns0(1232, false)
	Replay(r, q)
	if len(r.Extra) != 2 || r.IsEdns0().UDPSize() != 1232 || r.IsEdns0().Do() {
		t.Fatal("did not reconstruct the transaction OPT")
	}
	q.Extra = nil
	Replay(r, q)
	if len(r.Extra) != 1 || r.IsEdns0() != nil {
		t.Fatal("ordinary additional record was removed or OPT survived")
	}
}
