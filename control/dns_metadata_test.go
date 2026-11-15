// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"encoding/binary"
	"math"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/internal/routingabi"
	"golang.org/x/sys/unix"
)

func dnsMetadataOOB(destination netip.AddrPort, seconds, nanos int64, mark uint32) []byte {
	oob := originalDestControlMessage(destination)
	var stamp [16]byte
	binary.NativeEndian.PutUint64(stamp[:], uint64(seconds))
	binary.NativeEndian.PutUint64(stamp[8:], uint64(nanos))
	oob = appendControlMessage(oob, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS_NEW, stamp[:])
	var value [4]byte
	binary.NativeEndian.PutUint32(value[:], mark)
	return appendControlMessage(oob, unix.SOL_SOCKET, unix.SO_MARK, value[:])
}

func TestDNSMetadataParsing(t *testing.T) {
	for _, destination := range []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.53:53"), netip.MustParseAddrPort("[2001:db8::53]:53"),
	} {
		for _, cookie := range []uint64{1, 1e9, math.MaxInt64} {
			oob := dnsMetadataOOB(destination, int64(cookie/1e9), int64(cookie%1e9), routingabi.DNS_METADATA_MARK)
			got, valid := parseUDPMetadata(oob)
			if !valid || !got.validDNS() || got.destination != destination || got.cookie != cookie {
				t.Fatalf("destination=%v cookie=%d metadata=%+v valid=%v", destination, cookie, got, valid)
			}
			if allocs := testing.AllocsPerRun(100, func() { parseUDPMetadata(oob) }); allocs != 0 {
				t.Fatalf("metadata parser allocated %v times", allocs)
			}
		}
	}
}

func TestDNSMetadataKeepsSocketDropReporting(t *testing.T) {
	destination := netip.MustParseAddrPort("192.0.2.53:53")
	oob := dnsMetadataOOB(destination, 1, 2, routingabi.DNS_METADATA_MARK)
	mapped := netip.AddrPortFrom(netip.AddrFrom16(destination.Addr().As16()), destination.Port())
	oob = append(oob, originalDestControlMessage(mapped)...)
	var dropped [4]byte
	binary.NativeEndian.PutUint32(dropped[:], 7)
	oob = appendControlMessage(oob, unix.SOL_SOCKET, unix.SO_RXQ_OVFL, dropped[:])
	if len(oob) > udpOOBSize {
		t.Fatalf("metadata and overflow need %d control bytes, have %d", len(oob), udpOOBSize)
	}
	got, valid := parseUDPMetadata(oob)
	if !valid || !got.validDNS() || got.destination != destination || got.cookie != 1e9+2 || socketDrops(oob) != 7 {
		t.Fatalf("metadata and drop report diverged: %+v valid=%v dropped=%d", got, valid, socketDrops(oob))
	}
}

func TestDNSMetadataRejectsIncompleteOrConflictingMessages(t *testing.T) {
	destination := netip.MustParseAddrPort("192.0.2.53:53")
	valid := dnsMetadataOOB(destination, 1, 2, routingabi.DNS_METADATA_MARK)
	for _, test := range []struct {
		name string
		oob  []byte
	}{
		{"missing all", nil},
		{"missing cookie and mark", originalDestControlMessage(destination)},
		{"missing mark", valid[:len(valid)-unix.CmsgSpace(4)]},
		{"zero cookie", dnsMetadataOOB(destination, 0, 0, routingabi.DNS_METADATA_MARK)},
		{"untrusted mark", dnsMetadataOOB(destination, 1, 2, routingabi.TPROXY_MARK)},
		{"negative seconds", dnsMetadataOOB(destination, -1, 2, routingabi.DNS_METADATA_MARK)},
		{"negative nanos", dnsMetadataOOB(destination, 1, -1, routingabi.DNS_METADATA_MARK)},
		{"nanos overflow", dnsMetadataOOB(destination, 1, 1e9, routingabi.DNS_METADATA_MARK)},
		{"seconds overflow", dnsMetadataOOB(destination, math.MaxInt64, 0, routingabi.DNS_METADATA_MARK)},
		{"sum overflow", dnsMetadataOOB(destination, math.MaxInt64/1_000_000_000, math.MaxInt64%1_000_000_000+1, routingabi.DNS_METADATA_MARK)},
		{"short mark", appendControlMessage(valid, unix.SOL_SOCKET, unix.SO_MARK, []byte{1})},
		{"duplicate mark", appendControlMessage(valid, unix.SOL_SOCKET, unix.SO_MARK, make([]byte, 4))},
		{"short timestamp", appendControlMessage(valid, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS_NEW, make([]byte, 8))},
		{"duplicate timestamp", appendControlMessage(valid, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS_NEW, make([]byte, 16))},
		{"conflicting destination", append(append([]byte(nil), valid...), originalDestControlMessage(netip.MustParseAddrPort("192.0.2.54:53"))...)},
		{"truncated header", append(append([]byte(nil), valid...), 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			metadata, ok := parseUDPMetadata(test.oob)
			if ok && metadata.validDNS() {
				t.Fatalf("accepted metadata %+v", metadata)
			}
		})
	}
}

func TestDNSHandoffConsumeValidatesTuple(t *testing.T) {
	collection, _ := routingKernelFixture(t, nil, 1, nil)
	m := collection.Maps["dns_handoff_map"]
	source, destination := netip.MustParseAddrPort("192.0.2.1:12345"), netip.MustParseAddrPort("192.0.2.53:53")
	for _, field := range []string{"source address", "source port", "destination address", "destination port", "protocol", "valid"} {
		t.Run(field, func(t *testing.T) {
			handoff := bpfDnsHandoff{Result: bpfRoutingResult{SourceOrigin: uint8(plugin.SourceLAN), Generation: 7}}
			handoff.Reply.Tuple = tuplesKey(source, destination, unix.IPPROTO_UDP)
			switch field {
			case "source address":
				handoff.Reply.Tuple.Sip.U6Addr8[15]++
			case "source port":
				handoff.Reply.Tuple.Sport++
			case "destination address":
				handoff.Reply.Tuple.Dip.U6Addr8[15]++
			case "destination port":
				handoff.Reply.Tuple.Dport++
			case "protocol":
				handoff.Reply.Tuple.L4proto = unix.IPPROTO_TCP
			}
			cookie := uint64(17)
			if err := m.Update(cookie, handoff, ebpf.UpdateNoExist); err != nil {
				t.Fatal(err)
			}
			got, err := retrieveDNSRoutingResult(m, source, destination, cookie)
			if field == "valid" {
				if err != nil || got.bpfRoutingResult != handoff.Result || got.dns.cookie != cookie || got.dns.reply != handoff.Reply {
					t.Fatalf("handoff=%+v error=%v", got, err)
				}
			} else if err == nil || got != nil {
				t.Fatalf("accepted mismatched %s: %+v", field, got)
			}
			if got, err := retrieveDNSRoutingResult(m, source, destination, cookie); err == nil || got != nil {
				t.Fatalf("consumed cookie was reused: %+v error=%v", got, err)
			}
		})
	}
	for _, cookie := range []uint64{0, math.MaxInt64 + 1} {
		if got, err := retrieveDNSRoutingResult(m, source, destination, cookie); err == nil || got != nil {
			t.Fatalf("accepted invalid cookie %d", cookie)
		}
	}
}

func TestDNSReplyMetadataIsPerPacket(t *testing.T) {
	first, second := dnsReplyOOB(17), dnsReplyOOB(math.MaxInt64)
	for i, oob := range [][]byte{first, second} {
		messages, err := unix.ParseSocketControlMessage(oob)
		if err != nil || len(messages) != 2 {
			t.Fatalf("messages=%v error=%v", messages, err)
		}
		if messages[0].Header.Level != unix.SOL_SOCKET || messages[0].Header.Type != unix.SO_MARK || binary.NativeEndian.Uint32(messages[0].Data) != routingabi.DNS_REPLY_MARK {
			t.Fatalf("reply mark: %+v", messages[0])
		}
		if messages[1].Header.Level != unix.SOL_SOCKET || messages[1].Header.Type != unix.SCM_TXTIME || binary.NativeEndian.Uint64(messages[1].Data) != []uint64{17, math.MaxInt64}[i] {
			t.Fatalf("reply cookie: %+v", messages[1])
		}
	}
}
