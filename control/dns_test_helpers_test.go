/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"time"

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

func testDNSQueryKey(qi queryInfo, variant string) dnsQueryKey {
	return dnsQueryKey{queryInfo: qi, qclass: dnsmessage.ClassINET, variant: variant}
}

func testDNSCacheKey(qi queryInfo) dnsCacheKey {
	return dnsCacheKey{queryInfo: qi}
}

func testDNSFlightKey(qi queryInfo, variant string) dnsFlightKey {
	return dnsFlightKey{query: testDNSQueryKey(qi, variant)}
}

func testPlannedRRSeconds(plan *responsePlan, rr plannedRR) int {
	return deadlineSeconds(rr.absoluteDeadline, plan.observedAt)
}

func testViewDeadlineSeconds(plan *responsePlan, deadline time.Time) int {
	if deadline.IsZero() {
		return 0
	}
	return int(deadline.Sub(plan.observedAt) / time.Second)
}

func getTestDNSCache(c *commonDnsCache, key dnsCacheKey) []*DnsCache {
	if !c.FillInto(key, new(dnsmessage.Msg)) {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	elem := c.cache[key]
	if elem == nil {
		return nil
	}
	entry := elem.Value.(*cacheEntry)
	return append([]*DnsCache(nil), entry.value...)
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
