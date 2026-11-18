// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/internal/routingabi"
)

func TestDomainDirectKernelActivity(t *testing.T) {
	collection, state := routingKernelFixture(t, nil, 0, func(spec *ebpf.CollectionSpec) {
		spec.Maps["domain_activity_events"].MaxEntries = uint32(os.Getpagesize())
	})
	setRule := func(rule string) {
		t.Helper()
		matcher, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", rule))
		matcher.bpf = state
		if err := matcher.BuildKernspace(); err != nil {
			t.Fatal(err)
		}
	}
	const direct = "dport(443) -> direct(mark:37)"
	setRule(direct)
	slots, losses := collection.Maps["domain_activity_slots"], collection.Maps["domain_activity_losses"]
	reader, err := ringbuf.NewReader(collection.Maps["domain_activity_events"])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	ip := netip.MustParseAddr("198.51.100.1")
	other := ip.Next()
	src := netip.MustParseAddr("192.0.2.1")
	put := func(ip netip.Addr, token uint64) {
		t.Helper()
		if err := slots.Update(ip.As16(), bpfDomainActivitySlot{Token: token}, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	seen := func(ip netip.Addr) bpfDomainActivitySlot {
		t.Helper()
		var s bpfDomainActivitySlot
		if err := slots.Lookup(ip.As16(), &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	run := func(name string, packet []byte, verdict, mark uint32) {
		t.Helper()
		out := make([]byte, 256)
		got, err := collection.Programs[name].Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256), ContextOut: out})
		if err != nil || got != verdict || binary.NativeEndian.Uint32(out[8:12]) != mark {
			t.Fatalf("%s: verdict=%d mark=%d err=%v, want verdict=%d mark=%d", name, got, binary.NativeEndian.Uint32(out[8:12]), err, verdict, mark)
		}
	}
	drain := func() map[[16]byte]bpfDomainActivitySlot {
		t.Helper()
		reader.SetDeadline(time.Now())
		var record ringbuf.Record
		samples := make(map[[16]byte]bpfDomainActivitySlot)
		for {
			if err := reader.ReadInto(&record); err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					return samples
				}
				t.Fatal(err)
			}
			if len(record.RawSample) != 32 {
				t.Fatalf("unexpected event ABI: %d bytes", len(record.RawSample))
			}
			key := [16]byte(record.RawSample[:16])
			if _, duplicate := samples[key]; duplicate {
				t.Fatalf("duplicate event for %v", netip.AddrFrom16(key))
			}
			samples[key] = bpfDomainActivitySlot{Token: binary.NativeEndian.Uint64(record.RawSample[16:24]), LastSeenNs: binary.NativeEndian.Uint64(record.RawSample[24:32])}
		}
	}
	expect := func(ip netip.Addr, token uint64) {
		t.Helper()
		live, events := seen(ip), drain()
		if len(events) != 1 || live.Token != token || live.LastSeenNs == 0 || events[ip.As16()] != live {
			t.Fatalf("incorrect direct activity: live=%+v events=%+v", live, events)
		}
	}

	const next = ^uint32(0)
	const tcp, udp = consts.L4ProtoType_TCP, consts.L4ProtoType_UDP
	var port uint16 = 47000
	packet := func(ip netip.Addr, protocol consts.L4ProtoType) []byte {
		port++
		p, _ := routingKernelPacket(netip.AddrPortFrom(src, port), netip.AddrPortFrom(ip, 443), protocol)
		return p
	}
	for _, program := range []string{"lan_ingress_l2", "tproxy_wan_egress_l2"} {
		run(program, packet(other, udp), next, 37)
		if events := drain(); len(events) != 0 {
			t.Fatalf("unqualified IP produced event: %+v", events)
		}
		put(ip, 1)
		p := packet(ip, tcp)
		run(program, p, next, 37)
		run(program, p, next, 37) // Retransmitted SYN is coalesced.
		expect(ip, 1)

		put(ip, 2)
		p[len(p)-7] = 0x10 // ACK without payload still forwards with saved mark.
		run(program, p, next, 37)
		unowned := packet(ip, tcp)
		unowned[len(unowned)-7] = 0x10
		unowned = append(unowned, 1)
		binary.BigEndian.PutUint16(unowned[16:18], uint16(len(unowned)-14))
		run(program, unowned, next, 0)
		if live, events := seen(ip), drain(); live.LastSeenNs != 0 || len(events) != 0 {
			t.Fatalf("ACK-only or unowned data produced activity: %+v %+v", live, events)
		}
		p = append(p, 1)
		binary.BigEndian.PutUint16(p[16:18], uint16(len(p)-14))
		run(program, p, next, 37)
		expect(ip, 2)

		put(ip, 3)
		p = packet(ip, udp)
		run(program, p, next, 37)
		expect(ip, 3)
		put(ip, 4)
		setRule("dport(443) -> block")
		run(program, p, next, 37) // Only the cached route still permits it.
		expect(ip, 4)
		setRule(direct)

		put(ip, 5)
		inbound := packet(ip, udp)
		key := bpfTuplesKey{Sport: common.Htons(port), Dport: common.Htons(443), L4proto: 17}
		key.Sip.U6Addr8, key.Dip.U6Addr8 = src.As16(), ip.As16()
		if err := collection.Maps["udp_conn_state_map"].Update(key, bpfUdpConnState{IsWanIngressDirection: true}, ebpf.UpdateNoExist); err != nil {
			t.Fatal(err)
		}
		run(program, inbound, next, 0)
		setRule("dport(443) -> direct")
		fragment := append(packet(ip, udp), 0, 0, 0, 0)
		binary.BigEndian.PutUint16(fragment[16:18], uint16(len(fragment)-14))
		binary.BigEndian.PutUint16(fragment[20:22], 0x2000)
		binary.BigEndian.PutUint16(fragment[38:40], uint16(len(fragment)-34))
		run(program, fragment, next, 0)
		setRule(direct)
		if err := collection.Maps["exited_map"].Update(uint32(0), uint8(routingabi.DAEMON_STOPPING), ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		run(program, packet(ip, tcp), next, 37)
		setKernelOffline(t, collection, true)
		run(program, packet(ip, udp), next, 0)
		setKernelOffline(t, collection, false)
		if live, events := seen(ip), drain(); live.LastSeenNs != 0 || len(events) != 0 {
			t.Fatalf("fragment/inbound reply/stopping/offline flow produced activity: %+v %+v", live, events)
		}

		setRule("dport(53) -> direct(mark:37)")
		for _, proto := range []consts.L4ProtoType{tcp, udp} {
			port++
			dns, _ := routingKernelPacket(netip.AddrPortFrom(src, port), netip.AddrPortFrom(ip, 53), proto)
			run(program, dns, 7, 0)
		}
		if live, events := seen(ip), drain(); live.LastSeenNs != 0 || len(events) != 0 {
			t.Fatalf("captured DNS produced direct activity: %+v %+v", live, events)
		}
		prepared := prepareFlowRulesForTest(t, "dport(53) -> must", "dport(53) -> direct(mark:37)")
		matcher, _ := routingMatcherForTest(t, prepared)
		matcher.bpf = state
		if err := matcher.BuildKernspace(); err != nil {
			t.Fatal(err)
		}
		for _, proto := range []consts.L4ProtoType{tcp, udp} {
			for token := uint64(6); token <= 7; token++ {
				put(ip, token)
				if token == 6 {
					port++
				}
				dns, _ := routingKernelPacket(netip.AddrPortFrom(src, port), netip.AddrPortFrom(ip, 53), proto)
				if token == 7 && proto == tcp {
					dns[len(dns)-7] = 0x10 // Payload on the saved TCP flow, not another SYN.
					dns = append(dns, 1)
					binary.BigEndian.PutUint16(dns[16:18], uint16(len(dns)-14))
				}
				run(program, dns, next, 37)
				expect(ip, token)
			}
		}
		setRule(direct)
	}

	// A full queue loses hints, not authoritative last-seen values.
	if err := slots.Delete(ip.As16()); err != nil {
		t.Fatal(err)
	}
	active := os.Getpagesize()/40 + 3 // 32-byte records and 8-byte ring headers.
	first := netip.MustParseAddr("203.0.113.1")
	for i, addr := 0, first; i < active; i, addr = i+1, addr.Next() {
		put(addr, uint64(i+1))
		run("lan_ingress_l2", packet(addr, udp), next, 37)
	}
	var lost uint64
	if err := losses.Lookup(uint32(0), &lost); err != nil {
		t.Fatal(err)
	}
	events := drain()
	if lost == 0 || int(lost)+len(events) != active {
		t.Fatalf("unexpected ring overflow: active=%d events=%d lost=%d", active, len(events), lost)
	}
	var cursor ebpf.MapBatchCursor
	keys, values := make([][16]byte, 64), make([]bpfDomainActivitySlot, 64)
	recovered := 0
	for {
		n, err := slots.BatchLookup(&cursor, keys, values, nil)
		for i := range n {
			if values[i].LastSeenNs == 0 {
				continue
			}
			if event, ok := events[keys[i]]; !ok {
				recovered++
			} else if event != values[i] {
				t.Fatalf("event does not match slot: %+v != %+v", event, values[i])
			}
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if recovered != int(lost) {
		t.Fatalf("slot rescan did not recover all misses: %d of %d", recovered, lost)
	}
}

func TestDomainDirectKernelRenewsRegistry(t *testing.T) {
	collection, state := routingKernelFixture(t, nil, 0, func(spec *ebpf.CollectionSpec) {
		spec.Maps["domain_activity_events"].MaxEntries = uint32(os.Getpagesize())
	})
	matcher, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", "domain(full: target.example) && dport(443) -> direct(mark:37)"))
	matcher.bpf = state
	if err := matcher.BuildKernspace(); err != nil {
		t.Fatal(err)
	}
	feed, err := newDomainDirectFeed(collection.Maps["domain_activity_slots"], collection.Maps["domain_activity_events"], collection.Maps["domain_activity_losses"])
	if err != nil {
		t.Fatal(err)
	}
	core := &controlPlaneCore{bpf: state}
	const window = 10 * time.Second
	g := newDomainRegistry(int(state.DomainRoutingMap.MaxEntries()), window, core.writeDomainBitmaps, core.deleteDomainBitmaps)
	g.direct = feed
	defer g.Close()
	const domain = "target.example."
	at := time.Now().Add(-window / 2)
	bitmap := matcher.domainMatcher.MatchDomainBitmap(domain)
	produce := func(source netip.AddrPort, ip netip.Addr) {
		t.Helper()
		g.Upsert(domain, ip, bitmap, 1, at)
		p, _ := routingKernelPacket(source, netip.AddrPortFrom(ip, 443), consts.L4ProtoType_UDP)
		out := make([]byte, 256)
		verdict, err := collection.Programs["lan_ingress_l2"].Run(&ebpf.RunOptions{Data: p, Context: make([]byte, 256), ContextOut: out})
		if err != nil || verdict != ^uint32(0) || binary.NativeEndian.Uint32(out[8:12]) != 37 {
			t.Fatalf("activity changed kernel-direct verdict/mark: %d/%d %v", verdict, binary.NativeEndian.Uint32(out[8:12]), err)
		}
	}
	first := netip.MustParseAddr("198.51.100.1")
	for i, addr := 0, first; i < os.Getpagesize()/40; i, addr = i+1, addr.Next() {
		produce(netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(47000+i)), addr)
	}
	before, err := feed.lossEpoch()
	if err != nil || before != 0 {
		t.Fatalf("ring unexpectedly overflowed before its last sample: %d, %v", before, err)
	}
	last := netip.MustParseAddr("2001:db8::1")
	produce(netip.MustParseAddrPort("[2001:db8::2]:47000"), last)
	if lost, err := feed.lossEpoch(); err != nil || lost != 1 {
		t.Fatalf("IPv6 event did not overflow the ring: %d, %v", lost, err)
	}
	g.Start()

	oldDeadline := at.Add(window)
	var firstDeadline, lastDeadline time.Time
	for stop := time.Now().Add(3 * time.Second); time.Now().Before(stop); time.Sleep(20 * time.Millisecond) {
		g.Sweep(time.Now())
		g.mu.Lock()
		firstDeadline = g.byName[domain].addresses[first].retainUntil
		lastDeadline = g.byName[domain].addresses[last].retainUntil
		g.mu.Unlock()
		if firstDeadline.After(oldDeadline) && lastDeadline.After(oldDeadline) {
			break
		}
	}
	if !firstDeadline.After(oldDeadline) || !lastDeadline.After(oldDeadline) {
		t.Fatalf("real direct activity did not renew ordinary/overflow pairs: %v / %v, old deadline %v", firstDeadline, lastDeadline, oldDeadline)
	}
	g.Sweep(oldDeadline.Add(g.activityLag))
	if !g.Verify(domain, first).Paired || !g.Verify(domain, last).Paired {
		t.Fatal("renewed pair was collected at its previous deadline")
	}
	g.Sweep(lastDeadline.Add(g.activityLag))
	if g.Verify(domain, first).Paired || g.Verify(domain, last).Paired {
		t.Fatal("the direct renewal survived its new deadline without more packets")
	}
}
