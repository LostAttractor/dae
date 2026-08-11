/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"

	dnsmessage "github.com/miekg/dns"
)

func testDNSQuery(name string, qtype uint16, id uint16) *dnsmessage.Msg {
	return &dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{
			Id:               id,
			RecursionDesired: true,
		},
		Question: []dnsmessage.Question{{
			Name:   name,
			Qtype:  qtype,
			Qclass: dnsmessage.ClassINET,
		}},
	}
}

func testARecord(name, ip string) *dnsmessage.A {
	return &dnsmessage.A{
		Hdr: dnsmessage.RR_Header{
			Name:   name,
			Rrtype: dnsmessage.TypeA,
			Class:  dnsmessage.ClassINET,
			Ttl:    60,
		},
		A: net.ParseIP(ip).To4(),
	}
}

func testAAAARecord(name, ip string) *dnsmessage.AAAA {
	return &dnsmessage.AAAA{
		Hdr: dnsmessage.RR_Header{
			Name:   name,
			Rrtype: dnsmessage.TypeAAAA,
			Class:  dnsmessage.ClassINET,
			Ttl:    60,
		},
		AAAA: net.ParseIP(ip),
	}
}

func testCNAMERecord(name, target string) *dnsmessage.CNAME {
	return &dnsmessage.CNAME{
		Hdr: dnsmessage.RR_Header{
			Name:   name,
			Rrtype: dnsmessage.TypeCNAME,
			Class:  dnsmessage.ClassINET,
			Ttl:    60,
		},
		Target: target,
	}
}

func testSOARecord(name string) *dnsmessage.SOA {
	return &dnsmessage.SOA{
		Hdr: dnsmessage.RR_Header{
			Name:   name,
			Rrtype: dnsmessage.TypeSOA,
			Class:  dnsmessage.ClassINET,
			Ttl:    60,
		},
		Ns:      "ns1." + name,
		Mbox:    "hostmaster." + name,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  60,
	}
}
