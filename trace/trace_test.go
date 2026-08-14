//go:build trace

package trace

import (
	"bytes"
	"strings"
	"syscall"
	"testing"
)

func TestTraceBPFSpec(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	events := spec.Maps["events"]
	if events == nil {
		t.Fatal("events ring is missing from BPF maps")
	}
	if got := events.MaxEntries; got != 1<<24 {
		t.Fatalf("events ring size = %d, want %d", got, 1<<24)
	}
	variable := spec.Variables["tracing_cfg"]
	if variable == nil {
		t.Fatal("tracing_cfg is missing from BPF variables")
	}
	if err := variable.Set(struct {
		port      uint16
		l4Proto   uint16
		ipVersion uint8
		pad       uint8
	}{port: Htons(53), l4Proto: syscall.IPPROTO_UDP, ipVersion: 6}); err != nil {
		t.Fatalf("set tracing_cfg: %v", err)
	}
}

func TestWriteTraceEventsUsesPerEventFields(t *testing.T) {
	oldKallsyms := kallsyms
	kallsyms = []Symbol{{Addr: 1, Name: "first"}, {Addr: 2, Name: "second"}}
	defer func() { kallsyms = oldKallsyms }()

	events := []traceEvent{
		{
			Pc: 1, Skb: 1, L3Proto: syscall.ETH_P_IP, L4Proto: syscall.IPPROTO_UDP,
			Saddr: [16]byte{192, 0, 2, 1}, Daddr: [16]byte{198, 51, 100, 2},
			Sport: Htons(1000), Dport: Htons(53), PayloadLen: 10,
		},
		{
			Pc: 2, Skb: 1, L3Proto: syscall.ETH_P_IPV6, L4Proto: syscall.IPPROTO_TCP,
			Saddr: [16]byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			Daddr: [16]byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
			Sport: Htons(443), Dport: Htons(2000), TcpFlags: 0x12, PayloadLen: 20,
		},
	}
	var output bytes.Buffer
	if err := writeTraceEvents(&output, events, nil, false); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2: %q", len(lines), output.String())
	}
	if !strings.Contains(lines[0], "192.0.2.1:1000 > 198.51.100.2:53") || !strings.Contains(lines[0], "payload_len=10") || strings.Contains(lines[0], "tcp_flags=") {
		t.Fatalf("first line uses wrong event fields: %q", lines[0])
	}
	if !strings.Contains(lines[1], "[2001:db8::1]:443 > [2001:db8::2]:2000") || !strings.Contains(lines[1], "tcp_flags=.S") || !strings.Contains(lines[1], "payload_len=20") || !strings.Contains(lines[1], "incomplete") {
		t.Fatalf("second line uses wrong event fields: %q", lines[1])
	}
}

func TestEventAccumulatorDropsCompletedNonDropTrace(t *testing.T) {
	accumulator := newEventAccumulator()
	event := traceEvent{Skb: 1}
	if _, write := accumulator.add(event, "ip_rcv", true); write {
		t.Fatal("non-terminal event should not be written")
	}
	if _, write := accumulator.add(event, "kfree_skbmem", true); write {
		t.Fatal("drop-only trace without a drop reason should not be written")
	}
	if len(accumulator.events) != 0 || len(accumulator.symbols) != 0 {
		t.Fatal("completed trace was retained in accumulator")
	}
}
