// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	dnsmessage "github.com/miekg/dns"
	"net"
)

func testQuery(name string, qtype uint16, id uint16) *dnsmessage.Msg {
	m := new(dnsmessage.Msg).SetQuestion(name, qtype)
	m.Id = id
	return m
}

func testARecord(name, ip string) *dnsmessage.A {
	return &dnsmessage.A{Hdr: dnsmessage.RR_Header{Name: name, Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60}, A: net.ParseIP(ip).To4()}
}
