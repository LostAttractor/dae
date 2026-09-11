package transport

import (
	"context"
	dns "github.com/daeuniverse/dae-plugin-dns-router/policy"
	"github.com/daeuniverse/dae/common/netutils"
	dnsmessage "github.com/miekg/dns"
	"net"
	"testing"
)

func newTestDNSForwarder(t testing.TB, scheme dns.UpstreamScheme, args dialArgument) DnsForwarder {
	t.Helper()
	u := &dns.Upstream{Scheme: scheme, Ip46: new(netutils.Ip46)}
	_, protocols := u.SupportedNetworks()
	args.networkType.L4Proto = protocols[0]
	f, err := newDnsForwarder(context.Background(), u, args)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func testDNSQuery(name string, qtype uint16, id uint16) *dnsmessage.Msg {
	m := new(dnsmessage.Msg).SetQuestion(name, qtype)
	m.Id = id
	return m
}

func testARecord(name, ip string) *dnsmessage.A {
	return &dnsmessage.A{Hdr: dnsmessage.RR_Header{Name: name, Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60}, A: net.ParseIP(ip).To4()}
}
