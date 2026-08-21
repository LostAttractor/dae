//go:build trace && (amd64 || arm64 || riscv64 || loong64 || ppc64 || ppc64le)

package trace

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
)

func TestTraceBPFSpec(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{
		"kprobe_skb_1",
		"kprobe_skb_2",
		"kprobe_skb_3",
		"kprobe_skb_4",
		"kprobe_skb_5",
		"kprobe_skb_lifetime_termination",
		"raw_tracepoint_consume_skb",
		"raw_tracepoint_kfree_skb_legacy",
		"raw_tracepoint_kfree_skb_reason",
		"raw_tracepoint_napi_gro_receive_entry",
		"raw_tracepoint_napi_gro_receive_exit",
		"raw_tracepoint_napi_gro_frags_entry",
		"raw_tracepoint_napi_gro_frags_exit",
	} {
		program := spec.Programs[name]
		if program == nil {
			t.Errorf("BPF program %q is missing", name)
			continue
		}
		if strings.HasPrefix(name, "raw_tracepoint_") && program.Type != ebpf.RawTracepoint {
			t.Errorf("BPF program %q type = %s, want raw tracepoint", name, program.Type)
		}
	}
	for i := 1; i <= 5; i++ {
		name := fmt.Sprintf("kprobe_multi_skb_%d", i)
		program := spec.Programs[name]
		if program == nil {
			t.Errorf("BPF program %q is missing", name)
			continue
		}
		if program.AttachType != ebpf.AttachTraceKprobeMulti {
			t.Errorf("BPF program %q attach type = %s, want kprobe-multi", name, program.AttachType)
		}
	}
	for name := range spec.Programs {
		if strings.HasPrefix(name, "kprobe_skb_drop_") {
			t.Errorf("obsolete terminal/drop program %q remains", name)
		}
	}
	for _, name := range []string{
		"kprobe_skb_lifetime_termination",
		"raw_tracepoint_consume_skb",
		"raw_tracepoint_kfree_skb_legacy",
		"raw_tracepoint_kfree_skb_reason",
		"raw_tracepoint_napi_gro_receive_exit",
		"raw_tracepoint_napi_gro_frags_exit",
	} {
		if !programCallsHelper(spec.Programs[name], asm.FnRingbufOutput) {
			t.Errorf("terminal program %q does not emit an event", name)
		}
	}

	events := spec.Maps["events"]
	if events == nil || events.Type != ebpf.RingBuf || events.MaxEntries != 1<<24 {
		t.Fatalf("events map = %#v, want a 16 MiB ring buffer", events)
	}
	states := spec.Maps["trace_states"]
	if states == nil || states.Type != ebpf.Hash || states.MaxEntries != 4096 {
		t.Fatalf("trace_states map = %#v, want 4096-entry non-LRU hash", states)
	}
	var traceStateType *btf.Struct
	if err := spec.Types.TypeByName("trace_state", &traceStateType); err != nil {
		t.Fatalf("find BPF trace state type: %v", err)
	}
	wantTraceStateMembers := []string{"generation", "next_sequence", "active_producers", "closing", "terminal_emitted", "terminal_event"}
	if len(traceStateType.Members) != len(wantTraceStateMembers) {
		t.Fatalf("trace state members = %#v", traceStateType.Members)
	}
	for i, want := range wantTraceStateMembers {
		if traceStateType.Members[i].Name != want {
			t.Fatalf("trace state member %d = %q, want %q", i, traceStateType.Members[i].Name, want)
		}
	}
	runtimeState := spec.Maps["runtime"]
	if runtimeState == nil || runtimeState.Type != ebpf.Array || runtimeState.MaxEntries != 1 || runtimeState.ValueSize != 48 {
		t.Fatalf("runtime map = %#v, want one-entry 48-byte array", runtimeState)
	}
	control := spec.Maps["control"]
	if control == nil || control.Type != ebpf.Array || control.MaxEntries != 1 || control.KeySize != 4 || control.ValueSize != 4 {
		t.Fatalf("control map = %#v, want one-entry uint32 array", control)
	}
	groPending := spec.Maps["gro_pending"]
	if groPending == nil || groPending.Type != ebpf.PerCPUArray || groPending.MaxEntries != 2 || groPending.ValueSize != 8 {
		t.Fatalf("gro_pending map = %#v, want two-entry per-CPU uint64 array", groPending)
	}

	var eventType *btf.Struct
	if err := spec.Types.TypeByName("event", &eventType); err != nil {
		t.Fatalf("find BPF event type: %v", err)
	}
	eventSize, err := btf.Sizeof(eventType)
	if err != nil {
		t.Fatalf("size BPF event type: %v", err)
	}
	if got := binary.Size(traceEvent{}); got != eventSize {
		t.Fatalf("Go event size = %d, BPF event size = %d", got, eventSize)
	}

	variable := spec.Variables["tracing_cfg"]
	if variable == nil {
		t.Fatal("tracing_cfg is missing from BPF variables")
	}
	if err := variable.Set(bpfTracingConfig{
		NotDroppedReason: 0,
		ConsumedReason:   1,
		Port:             Htons(53),
		L4Proto:          syscall.IPPROTO_UDP,
		IpVsn:            6,
	}); err != nil {
		t.Fatalf("set tracing_cfg: %v", err)
	}
}

func TestNearestSymbolHandlesEmptyAndFullAddressRange(t *testing.T) {
	original := kallsyms
	t.Cleanup(func() { kallsyms = original })

	kallsyms = nil
	if got := NearestSymbol(1).Name; got != "unknown" {
		t.Fatalf("empty symbol lookup = %q, want unknown", got)
	}
	kallsyms = []Symbol{{Name: "hidden-first"}, {Name: "hidden-last"}}
	if got := NearestSymbol(1).Name; got != "unknown" {
		t.Fatalf("zero-address symbol lookup = %q, want unknown", got)
	}

	kallsyms = []Symbol{
		{Name: "low", Addr: 0x100},
		{Name: "kernel", Addr: 0xffff_8000_0000_0000},
		{Name: "kernel-next", Addr: 0xffff_8000_0000_1000},
	}
	if got := NearestSymbol(0xffff_8000_0000_0800).Name; got != "kernel" {
		t.Fatalf("high-address lookup = %q, want kernel", got)
	}
}

func TestCompiledProducerStateTransitions(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}

	for name, producer := range spec.Programs {
		if !strings.HasPrefix(name, "kprobe_skb_") &&
			!strings.HasPrefix(name, "kprobe_multi_skb_") &&
			!strings.HasPrefix(name, "raw_tracepoint_") {
			continue
		}
		if strings.HasSuffix(name, "_gro_receive_entry") || strings.HasSuffix(name, "_gro_frags_entry") {
			continue
		}
		references := make(map[string]int)
		for _, instruction := range producer.Instructions {
			if reference := instruction.Reference(); reference != "" {
				references[reference]++
			}
		}
		if references["control"] < 2 {
			t.Errorf("BPF producer %q has %d control references, want initial check and post-increment recheck", name, references["control"])
		}
		lifetimeEnd := name == "kprobe_skb_lifetime_termination" ||
			strings.HasSuffix(name, "_gro_receive_exit") || strings.HasSuffix(name, "_gro_frags_exit")
		if references["runtime"] == 0 ||
			(!lifetimeEnd && !programCallsHelper(producer, asm.FnMapUpdateElem)) ||
			!programCallsHelper(producer, asm.FnRingbufOutput) {
			t.Errorf("BPF producer %q does not account for execution, admit, and emit structurally", name)
		}
		if !programCallsHelper(producer, asm.FnMapDeleteElem) {
			t.Errorf("BPF producer %q cannot finalize a terminal trace after the last concurrent producer", name)
		}
	}
}

func programCallsHelper(program *ebpf.ProgramSpec, helper asm.BuiltinFunc) bool {
	for _, instruction := range program.Instructions {
		if instruction.IsBuiltinCall() && asm.BuiltinFunc(instruction.Constant) == helper {
			return true
		}
	}
	return false
}

func TestRawKfreeReasonABIDetection(t *testing.T) {
	voidType := &btf.Void{}
	skb := &btf.Struct{Name: "sk_buff", Size: 1}
	dropReason := &btf.Enum{Name: "skb_drop_reason", Size: 4}
	legacy := &btf.Typedef{Name: "btf_trace_kfree_skb", Type: &btf.Pointer{Target: &btf.FuncProto{Params: []btf.FuncParam{
		{Name: "data", Type: &btf.Pointer{Target: voidType}},
		{Name: "skb", Type: &btf.Pointer{Target: skb}},
		{Name: "location", Type: &btf.Pointer{Target: voidType}},
	}}}}
	withReason := &btf.Typedef{Name: "btf_trace_kfree_skb", Type: &btf.Pointer{Target: &btf.FuncProto{Params: []btf.FuncParam{
		{Name: "data", Type: &btf.Pointer{Target: voidType}},
		{Name: "skb", Type: &btf.Pointer{Target: skb}},
		{Name: "location", Type: &btf.Pointer{Target: voidType}},
		{Name: "reason", Type: &btf.Const{Type: dropReason}},
	}}}}

	if typeHasDropReason(legacy) {
		t.Fatal("legacy kfree_skb tracepoint incorrectly has a reason")
	}
	if !typeHasDropReason(withReason) {
		t.Fatal("reason-aware kfree_skb tracepoint was not detected")
	}

	fixtures := []struct {
		name       string
		traceType  btf.Type
		reasons    *btf.Enum
		wantReason bool
	}{
		{
			name:      "legacy ABI",
			traceType: legacy,
			reasons:   &btf.Enum{Name: "skb_drop_reason", Size: 4},
		},
		{
			name:      "Linux 5.17 reason ABI without not-dropped sentinel",
			traceType: withReason,
			reasons: &btf.Enum{Name: "skb_drop_reason", Size: 4, Values: []btf.EnumValue{
				{Name: "SKB_DROP_REASON_NOT_SPECIFIED", Value: 0},
				{Name: "SKB_DROP_REASON_NO_SOCKET", Value: 2},
			}},
		},
		{
			name:      "reason ABI with classification sentinels",
			traceType: withReason,
			reasons: &btf.Enum{Name: "skb_drop_reason", Size: 4, Values: []btf.EnumValue{
				{Name: "SKB_NOT_DROPPED_YET", Value: 0},
				{Name: "SKB_CONSUMED", Value: 1},
			}},
			wantReason: true,
		},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			_, config, err := dropReasonsFromEnum(fixture.reasons)
			if err != nil {
				t.Fatal(err)
			}
			if got := canClassifyKfreeReason(fixture.traceType, config); got != fixture.wantReason {
				t.Fatalf("reason classifier selected = %t, want %t", got, fixture.wantReason)
			}
		})
	}
}

func TestKernelTracepointDiscovery(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Skipf("kernel BTF is unavailable: %v", err)
	}
	targets, reasons, config, hasReason, err := searchAvailableTargets()
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) == 0 {
		t.Fatal("no generic skb probe targets discovered")
	}
	if hasReason {
		if got := reasons[config.notDropped]; got != "SKB_NOT_DROPPED_YET" {
			t.Fatalf("not-dropped reason = %q", got)
		}
		if consumed, ok := findDropReason(reasons, "SKB_CONSUMED"); ok && config.consumed != consumed {
			t.Fatalf("consumed reason = %d, want %d", config.consumed, consumed)
		}
	}
}

func TestTraceBPFVerifierLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("loading trace BPF requires root")
	}
	unsetReason := ^uint32(0)
	objs, multiLoaded, err := rewriteAndLoadBpf(4, syscall.IPPROTO_UDP, 53, dropReasonConfig{
		notDropped: unsetReason,
		consumed:   unsetReason,
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if multiLoaded {
		t.Fatal("legacy verifier fixture unexpectedly loaded multi-kprobe programs")
	}
	defer objs.Close()

	key := uint32(0)
	var stopped uint32
	if err := objs.control.Lookup(&key, &stopped); err != nil {
		t.Fatalf("read initial trace control: %v", err)
	}
	if stopped != 0 {
		t.Fatalf("initial trace control = %d, want running", stopped)
	}
	if err := stopTraceProducers(objs.control); err != nil {
		t.Fatal(err)
	}
	if err := objs.control.Lookup(&key, &stopped); err != nil {
		t.Fatalf("read stopped trace control: %v", err)
	}
	if stopped != 1 {
		t.Fatalf("stopped trace control = %d, want 1", stopped)
	}
}

func TestMultiProgramLoadFallbackUsesFreshLegacyLoad(t *testing.T) {
	want := &traceObjects{}
	var calls []bool
	got, multiLoaded, err := loadTraceObjectsWithFallback(true, func(multi bool) (*traceObjects, error) {
		calls = append(calls, multi)
		if multi {
			return nil, fmt.Errorf("program kprobe_multi_skb_1: %w", syscall.EINVAL)
		}
		return want, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != want || multiLoaded || fmt.Sprint(calls) != "[true false]" {
		t.Fatalf("fallback = (objs:%p multi:%t calls:%v), want fresh legacy load", got, multiLoaded, calls)
	}

	calls = nil
	wantErr := errors.New("verifier rejected program")
	_, _, err = loadTraceObjectsWithFallback(true, func(multi bool) (*traceObjects, error) {
		calls = append(calls, multi)
		return nil, wantErr
	})
	if !errors.Is(err, wantErr) || fmt.Sprint(calls) != "[true]" {
		t.Fatalf("non-attach failure was retried: err=%v calls=%v", err, calls)
	}
}

func findDropReason(reasons map[uint32]string, name string) (uint32, bool) {
	for value, candidate := range reasons {
		if candidate == name {
			return value, true
		}
	}
	return 0, false
}

func TestAccumulatorUsesExplicitTerminalAndDropFlags(t *testing.T) {
	accumulator := newEventAccumulator()
	base := traceEvent{Skb: 1, Generation: 10}
	if completed := accumulator.add(base); len(completed) != 0 {
		t.Fatal("ordinary event unexpectedly completed a trace")
	}
	drop := base
	drop.Sequence = 1
	drop.Flags = eventFlagDrop | eventFlagDropReason
	drop.DropReason = 7
	if completed := accumulator.add(drop); len(completed) != 0 {
		t.Fatal("drop event unexpectedly completed a trace")
	}
	terminal := base
	terminal.Sequence = 2
	terminal.Flags = eventFlagTerminal
	completed := accumulator.add(terminal)
	if len(completed) != 1 {
		t.Fatalf("completed traces = %d, want 1", len(completed))
	}
	if !completed[0].dropSeen || !completed[0].dropReasonAvailable || completed[0].dropReason != 7 || completed[0].truncated {
		t.Fatalf("completed trace flags were not retained: %#v", completed[0])
	}
	if !shouldWriteTrace(completed[0], true) {
		t.Fatal("drop-only mode rejected an explicitly dropped trace")
	}
}

func TestAccumulatorConsumeAndNonDropReasonsAreNotDrops(t *testing.T) {
	for _, event := range []traceEvent{
		{Skb: 1, Generation: 1, Flags: eventFlagTerminal | eventFlagConsume},
		{Skb: 2, Generation: 2, Flags: eventFlagTerminal | eventFlagDropReason, DropReason: 1},
	} {
		completed := newEventAccumulator().add(event)
		if len(completed) != 1 || completed[0].dropSeen || shouldWriteTrace(completed[0], true) {
			t.Fatalf("non-drop terminal was treated as a drop: %#v", completed)
		}
	}
}

func TestAccumulatorSeparatesReusedAddressByGeneration(t *testing.T) {
	accumulator := newEventAccumulator()
	accumulator.add(traceEvent{Skb: 1, Generation: 10, Sequence: 0})
	accumulator.add(traceEvent{Skb: 1, Generation: 11, Sequence: 0})
	completed := accumulator.add(traceEvent{Skb: 1, Generation: 11, Sequence: 1, Flags: eventFlagTerminal})
	if len(completed) != 1 || completed[0].events[0].Generation != 11 || completed[0].truncated {
		t.Fatalf("new generation completion = %#v", completed)
	}
	flushed := accumulator.flush()
	if len(flushed) != 1 || flushed[0].events[0].Generation != 10 || !flushed[0].truncated {
		t.Fatalf("terminal-lost old generation = %#v", flushed)
	}
}

func TestAccumulatorOrdersBySequenceAndDetectsLoss(t *testing.T) {
	accumulator := newEventAccumulator()
	accumulator.add(traceEvent{Skb: 1, Generation: 1, Sequence: 1})
	accumulator.add(traceEvent{Skb: 1, Generation: 1, Sequence: 0})
	completed := accumulator.add(traceEvent{Skb: 1, Generation: 1, Sequence: 2, Flags: eventFlagTerminal})
	if completed[0].truncated {
		t.Fatal("contiguous out-of-order events were marked truncated")
	}
	for i, event := range completed[0].events {
		if event.Sequence != uint32(i) {
			t.Fatalf("event %d has sequence %d", i, event.Sequence)
		}
	}

	accumulator.add(traceEvent{Skb: 2, Generation: 1, Sequence: 0})
	lost := accumulator.add(traceEvent{Skb: 2, Generation: 1, Sequence: 2, Flags: eventFlagTerminal})
	if len(lost) != 1 || !lost[0].truncated {
		t.Fatalf("sequence gap was not retained as truncation: %#v", lost)
	}
}

func TestAccumulatorEvictsOldestDeterministically(t *testing.T) {
	accumulator := newEventAccumulator()
	for i := uint64(0); i < maxPendingTraces; i++ {
		accumulator.add(traceEvent{Skb: i, Generation: 1})
	}
	evicted := accumulator.add(traceEvent{Skb: maxPendingTraces, Generation: 1})
	if len(evicted) != 1 || evicted[0].events[0].Skb != 0 || !evicted[0].truncated {
		t.Fatalf("evicted trace = %#v, want incomplete skb 0", evicted)
	}
	oldest := accumulator.order.Front().Value.(traceKey)
	if len(accumulator.traces) != maxPendingTraces || oldest.skb != 1 {
		t.Fatalf("pending state is not bounded FIFO: len=%d oldest=%v", len(accumulator.traces), oldest)
	}
}

func TestAccumulatorEventCapRetainsDropReason(t *testing.T) {
	accumulator := newEventAccumulator()
	accumulator.add(traceEvent{Skb: 1, Generation: 1, Flags: eventFlagDrop | eventFlagDropReason, DropReason: 7})
	for i := uint32(1); i <= maxEventsPerTrace; i++ {
		accumulator.add(traceEvent{Skb: 1, Generation: 1, Sequence: i})
	}
	completed := accumulator.add(traceEvent{Skb: 1, Generation: 1, Sequence: maxEventsPerTrace + 1, Flags: eventFlagTerminal})
	if len(completed) != 1 || len(completed[0].events) != maxEventsPerTrace {
		t.Fatalf("completed capped trace has %d events", len(completed[0].events))
	}
	if !completed[0].dropSeen || !completed[0].dropReasonAvailable || completed[0].dropReason != 7 || !completed[0].truncated {
		t.Fatalf("capped trace metadata was not retained: %#v", completed[0])
	}
}

func TestWriteTraceEventsTupleUnavailableAndRetainedReason(t *testing.T) {
	oldKallsyms := kallsyms
	kallsyms = []Symbol{{Addr: 1, Name: "first"}}
	defer func() { kallsyms = oldKallsyms }()

	trace := accumulatedTrace{
		dropSeen:            true,
		dropReason:          7,
		dropReasonAvailable: true,
		truncated:           true,
		events: []traceEvent{
			{Pc: 1, Skb: 1, Generation: 9, Sequence: 0},
			{
				Skb: 1, Generation: 9, Sequence: 1,
				Flags:   eventFlagTerminal | eventFlagTupleValid,
				L3Proto: syscall.ETH_P_IP, L4Proto: syscall.IPPROTO_UDP,
				Saddr: [16]byte{192, 0, 2, 1}, Daddr: [16]byte{198, 51, 100, 2},
				Sport: Htons(1000), Dport: Htons(53), PayloadLen: 10,
			},
		},
	}
	var output bytes.Buffer
	if err := writeTraceEvents(&output, trace, map[uint32]string{7: "TEST_DROP"}, false); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "gen=9") || !strings.Contains(lines[0], "tuple=unavailable") {
		t.Fatalf("unavailable tuple output is not readable: %q", output.String())
	}
	if !strings.Contains(lines[1], "192.0.2.1:1000 > 198.51.100.2:53") || !strings.Contains(lines[1], "kfree_skb(TEST_DROP)") || !strings.Contains(lines[1], "incomplete") {
		t.Fatalf("retained reason output is incomplete: %q", lines[1])
	}
}

func TestWriteTraceEventsMarksCoverageIncomplete(t *testing.T) {
	oldKallsyms := kallsyms
	kallsyms = []Symbol{{Addr: 1, Name: "first"}}
	defer func() { kallsyms = oldKallsyms }()

	var output bytes.Buffer
	trace := accumulatedTrace{events: []traceEvent{{Pc: 1, Skb: 1, Generation: 1}}}
	if err := writeTraceEvents(&output, trace, nil, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "first incomplete") {
		t.Fatalf("coverage-incomplete trace was not marked: %q", output.String())
	}
}

func TestRunClosersConcurrentlyIsBounded(t *testing.T) {
	const workers = 2
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	var active int32
	var maximum int32
	closers := make([]func() error, 4)
	for i := range closers {
		closers[i] = func() error {
			current := atomic.AddInt32(&active, 1)
			for old := atomic.LoadInt32(&maximum); current > old && !atomic.CompareAndSwapInt32(&maximum, old, current); old = atomic.LoadInt32(&maximum) {
			}
			started <- struct{}{}
			<-release
			atomic.AddInt32(&active, -1)
			return nil
		}
	}

	done := make(chan error, 1)
	go func() { done <- runClosersConcurrently(closers, workers) }()
	for range workers {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("parallel close workers did not start")
		}
	}
	select {
	case <-started:
		t.Fatal("close worker bound was exceeded")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&maximum); got != workers {
		t.Fatalf("maximum parallel closers = %d, want %d", got, workers)
	}
}

type fakeTraceControl struct {
	stopped atomic.Bool
}

func (c *fakeTraceControl) Update(key, value any, flags ebpf.MapUpdateFlags) error {
	mapKey, keyOK := key.(*uint32)
	stopped, valueOK := value.(*uint32)
	if !keyOK || !valueOK || *mapKey != 0 || (*stopped != 0 && *stopped != 1) || flags != ebpf.UpdateExist {
		return fmt.Errorf("unexpected control update: key=%v value=%v flags=%v", key, value, flags)
	}
	c.stopped.Store(*stopped == 1)
	return nil
}

type fakeTraceRuntime struct {
	active atomic.Uint64
}

func (r *fakeTraceRuntime) Lookup(_ any, valueOut any) error {
	state, ok := valueOut.(*bpfRuntimeState)
	if !ok {
		return fmt.Errorf("unexpected runtime output %T", valueOut)
	}
	state.ActiveProducers = r.active.Load()
	return nil
}

type stopAwareEventReader struct {
	control        *fakeTraceControl
	flushed        chan struct{}
	flushOnce      sync.Once
	flushedRunning atomic.Bool
	runtime        *fakeTraceRuntime
	flushedActive  atomic.Bool
}

func (r *stopAwareEventReader) Read() (ringbuf.Record, error) {
	<-r.flushed
	return ringbuf.Record{}, ringbuf.ErrFlushed
}

func (r *stopAwareEventReader) Flush() error {
	if !r.control.stopped.Load() {
		r.flushedRunning.Store(true)
	}
	if r.runtime != nil && r.runtime.active.Load() != 0 {
		r.flushedActive.Store(true)
	}
	r.flushOnce.Do(func() { close(r.flushed) })
	return nil
}

type fakeTraceOwner struct {
	closed atomic.Bool
	err    error
}

func (o *fakeTraceOwner) Close() error {
	o.closed.Store(true)
	return o.err
}

func TestProducerDetacherWaitDoneReturnsCleanupError(t *testing.T) {
	wantErr := errors.New("close owner")
	detacher := newProducerDetacher(nil, &fakeTraceControl{}, &fakeTraceOwner{err: wantErr})
	if err := detacher.start(); err != nil {
		t.Fatal(err)
	}
	detacher.releaseObjects()
	if err := detacher.waitDone(time.Second); !errors.Is(err, wantErr) {
		t.Fatalf("waitDone error = %v, want %v", err, wantErr)
	}
}

func TestProducerDetacherWaitDoneIsBounded(t *testing.T) {
	release := make(chan struct{})
	detacher := &producerDetacher{
		control:  &fakeTraceControl{},
		owner:    &fakeTraceOwner{},
		closers:  []func() error{func() error { <-release; return nil }},
		done:     make(chan struct{}),
		detached: make(chan struct{}),
		release:  make(chan struct{}),
	}
	if err := detacher.start(); err != nil {
		t.Fatal(err)
	}
	detacher.releaseObjects()
	if err := detacher.waitDone(time.Millisecond); err == nil {
		t.Fatal("waitDone did not report cleanup timeout")
	}
	close(release)
	if err := detacher.waitDone(time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestStopTraceProducersSetsControlMap(t *testing.T) {
	control := &fakeTraceControl{}
	if err := stopTraceProducers(control); err != nil {
		t.Fatal(err)
	}
	if !control.stopped.Load() {
		t.Fatal("control map was not stopped")
	}
}

func TestWaitForTraceProducersIsBounded(t *testing.T) {
	runtime := &fakeTraceRuntime{}
	runtime.active.Store(1)
	drained := make(chan error, 1)
	go func() { drained <- waitForTraceProducers(runtime, time.Second) }()
	time.Sleep(10 * time.Millisecond)
	runtime.active.Store(0)
	if err := <-drained; err != nil {
		t.Fatal(err)
	}

	runtime.active.Store(1)
	started := time.Now()
	if err := waitForTraceProducers(runtime, 15*time.Millisecond); err == nil {
		t.Fatal("active producer wait did not time out")
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("active producer wait was not bounded: %s", elapsed)
	}
}

func TestCancellationWaitsForActiveProducerBeforeFlush(t *testing.T) {
	control := &fakeTraceControl{}
	runtime := &fakeTraceRuntime{}
	runtime.active.Store(1)
	owner := &fakeTraceOwner{}
	detacher := newProducerDetacher(nil, control, owner)
	reader := &stopAwareEventReader{control: control, runtime: runtime, flushed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- readTraceEvents(ctx, runtime, reader, io.Discard, nil, false, probeCoverage{}, detacher)
	}()
	cancel()

	deadline := time.Now().Add(time.Second)
	for !control.stopped.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !control.stopped.Load() {
		t.Fatal("shutdown did not set the producer stop flag")
	}
	select {
	case <-reader.flushed:
		t.Fatal("ring buffer flushed before active producer drained")
	case <-time.After(20 * time.Millisecond):
	}
	runtime.active.Store(0)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("event reader did not flush after active producer drained")
	}
	if reader.flushedActive.Load() {
		t.Fatal("ring buffer observed an active producer during flush")
	}
	detacher.releaseObjects()
	select {
	case <-detacher.done:
	case <-time.After(time.Second):
		t.Fatal("detacher did not release BPF objects")
	}
}

func TestIncompleteCoverageIsWrittenToTraceOutput(t *testing.T) {
	control := &fakeTraceControl{}
	runtime := &fakeTraceRuntime{}
	owner := &fakeTraceOwner{}
	detacher := newProducerDetacher(nil, control, owner)
	reader := &stopAwareEventReader{control: control, runtime: runtime, flushed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output bytes.Buffer
	coverage := probeCoverage{discovered: 10, attached: 7}
	if err := readTraceEvents(ctx, runtime, reader, &output, nil, false, coverage, detacher); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "probe coverage attached=7 discovered=10 omitted=3") {
		t.Fatalf("coverage counts missing from trace output: %q", output.String())
	}
	detacher.releaseObjects()
	select {
	case <-detacher.done:
	case <-time.After(time.Second):
		t.Fatal("detacher did not release BPF objects")
	}
}

func TestCancellationDoesNotWaitForSlowDetachers(t *testing.T) {
	const closerCount = 512
	closerRelease := make(chan struct{})
	closers := make([]func() error, closerCount)
	for i := range closers {
		closers[i] = func() error {
			<-closerRelease
			return nil
		}
	}

	control := &fakeTraceControl{}
	owner := &fakeTraceOwner{}
	detacher := &producerDetacher{
		control:  control,
		owner:    owner,
		closers:  closers,
		done:     make(chan struct{}),
		detached: make(chan struct{}),
		release:  make(chan struct{}),
	}
	runtime := &fakeTraceRuntime{}
	reader := &stopAwareEventReader{control: control, runtime: runtime, flushed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- readTraceEvents(ctx, runtime, reader, io.Discard, nil, false, probeCoverage{}, detacher)
	}()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("event handling waited for slow link teardown")
	}
	if !control.stopped.Load() {
		t.Fatal("cancellation returned before stopping BPF producers")
	}
	if reader.flushedRunning.Load() {
		t.Fatal("ring buffer was flushed before stopping BPF producers")
	}
	if reader.flushedActive.Load() {
		t.Fatal("ring buffer was flushed while a BPF producer was active")
	}
	if owner.closed.Load() {
		t.Fatal("BPF objects closed before slow links detached")
	}

	detacher.releaseObjects()
	if owner.closed.Load() {
		t.Fatal("BPF objects closed while links were still attached")
	}
	close(closerRelease)
	select {
	case <-detacher.done:
	case <-time.After(2 * time.Second):
		t.Fatal("asynchronous link teardown did not complete")
	}
	if !owner.closed.Load() {
		t.Fatal("BPF objects were not closed after link teardown")
	}
}

type fakeProbeAttachment struct {
	closed   bool
	closeErr error
}

func (f *fakeProbeAttachment) Close() error {
	f.closed = true
	return f.closeErr
}

func TestGroupTargetsByPosition(t *testing.T) {
	groups := groupTargetsByPosition([]probeTarget{
		{name: "first", skbPosition: 1},
		{name: "third", skbPosition: 3},
		{name: "second", skbPosition: 1},
		{name: "ignored", skbPosition: 6},
	})
	if got := strings.Join(groups[0], ","); got != "first,second" {
		t.Fatalf("position 1 group = %q", got)
	}
	if got := strings.Join(groups[2], ","); got != "third" {
		t.Fatalf("position 3 group = %q", got)
	}
}

func TestAttachProbeGroupUsesSingleMultiLink(t *testing.T) {
	multi := &fakeProbeAttachment{}
	singleCalls := 0
	attached, attachedSymbols, err := attachProbeGroup(
		[]string{"one", "two"},
		true,
		func([]string) (probeAttachment, error) { return multi, nil },
		func(string) (probeAttachment, error) {
			singleCalls++
			return &fakeProbeAttachment{}, nil
		},
	)
	if err != nil || len(attached) != 1 || attachedSymbols != 2 || attached[0] != multi || singleCalls != 0 {
		t.Fatalf("multi attach = (%#v, symbols:%d, %v), single calls = %d", attached, attachedSymbols, err, singleCalls)
	}
}

func TestAttachProbeGroupFallsBackOnUnsupportedKernel(t *testing.T) {
	multiCalls := 0
	singleCalls := 0
	attached, attachedSymbols, err := attachProbeGroup(
		[]string{"one", "two"},
		false,
		func([]string) (probeAttachment, error) {
			multiCalls++
			return nil, link.ErrNotSupported
		},
		func(string) (probeAttachment, error) {
			singleCalls++
			return &fakeProbeAttachment{}, nil
		},
	)
	if err != nil || len(attached) != 2 || attachedSymbols != 2 || multiCalls != 0 || singleCalls != 2 {
		t.Fatalf("fallback attach = (%d, symbols:%d, %v), calls = multi:%d single:%d", len(attached), attachedSymbols, err, multiCalls, singleCalls)
	}
}

func TestAttachProbeGroupFallsBackWhenMultiIsUnsupported(t *testing.T) {
	multiCalls := 0
	singleCalls := 0
	attached, attachedSymbols, err := attachProbeGroup(
		[]string{"one", "two"},
		true,
		func([]string) (probeAttachment, error) {
			multiCalls++
			return nil, link.ErrNotSupported
		},
		func(string) (probeAttachment, error) {
			singleCalls++
			return &fakeProbeAttachment{}, nil
		},
	)
	if err != nil || len(attached) != 2 || attachedSymbols != 2 || multiCalls != 1 || singleCalls != 2 {
		t.Fatalf("unsupported multi fallback = (%d, symbols:%d, %v), calls = multi:%d single:%d", len(attached), attachedSymbols, err, multiCalls, singleCalls)
	}
}

func TestAttachProbeGroupRecursivelySplitsFailedMultiBatch(t *testing.T) {
	wantErr := fmt.Errorf("invalid symbol set: %w", os.ErrNotExist)
	singleCalls := 0
	multiCalls := 0
	attached, attachedSymbols, err := attachProbeGroup(
		[]string{"one", "bad", "two"},
		true,
		func(symbols []string) (probeAttachment, error) {
			multiCalls++
			for _, symbol := range symbols {
				if symbol == "bad" {
					return nil, wantErr
				}
			}
			return &fakeProbeAttachment{}, nil
		},
		func(string) (probeAttachment, error) {
			singleCalls++
			return &fakeProbeAttachment{}, nil
		},
	)
	if !errors.Is(err, wantErr) || len(attached) != 2 || attachedSymbols != 2 || multiCalls != 5 || singleCalls != 0 {
		t.Fatalf("split multi attach = (links:%d symbols:%d err:%v), calls = multi:%d single:%d", len(attached), attachedSymbols, err, multiCalls, singleCalls)
	}
}

func TestAttachProbeGroupDoesNotSplitGlobalFailure(t *testing.T) {
	multiCalls := 0
	wantErr := syscall.EPERM
	attached, attachedSymbols, err := attachProbeGroup(
		[]string{"one", "two", "three"},
		true,
		func([]string) (probeAttachment, error) {
			multiCalls++
			return nil, wantErr
		},
		func(string) (probeAttachment, error) {
			t.Fatal("global multi-attach failure fell back to single probes")
			return nil, nil
		},
	)
	if !errors.Is(err, wantErr) || len(attached) != 0 || attachedSymbols != 0 || multiCalls != 1 {
		t.Fatalf("global failure = (links:%d symbols:%d err:%v calls:%d)", len(attached), attachedSymbols, err, multiCalls)
	}
}

func TestAttachProbeGroupClosesFailedMultiBeforeFallback(t *testing.T) {
	partial := &fakeProbeAttachment{}
	singleCalls := 0
	attached, attachedSymbols, err := attachProbeGroup(
		[]string{"one", "two"},
		true,
		func([]string) (probeAttachment, error) { return partial, link.ErrNotSupported },
		func(string) (probeAttachment, error) {
			singleCalls++
			return &fakeProbeAttachment{}, nil
		},
	)
	if err != nil || !partial.closed || len(attached) != 2 || attachedSymbols != 2 || singleCalls != 2 {
		t.Fatalf("partial cleanup = closed:%t attached:%d symbols:%d calls:%d err:%v", partial.closed, len(attached), attachedSymbols, singleCalls, err)
	}

	partial = &fakeProbeAttachment{closeErr: errors.New("still attached")}
	singleCalls = 0
	attached, attachedSymbols, err = attachProbeGroup(
		[]string{"one"},
		true,
		func([]string) (probeAttachment, error) { return partial, link.ErrNotSupported },
		func(string) (probeAttachment, error) {
			singleCalls++
			return &fakeProbeAttachment{}, nil
		},
	)
	if err == nil || len(attached) != 0 || attachedSymbols != 0 || singleCalls != 0 {
		t.Fatalf("fallback proceeded after failed cleanup: attached:%d symbols:%d calls:%d err:%v", len(attached), attachedSymbols, singleCalls, err)
	}
}

func TestKprobeMultiVersionBoundary(t *testing.T) {
	if supportsKprobeMulti(internal.Version{5, 17, 99}) {
		t.Fatal("Linux 5.17 incorrectly enables kprobe-multi")
	}
	if !supportsKprobeMulti(internal.Version{5, 18, 0}) {
		t.Fatal("Linux 5.18 did not enable kprobe-multi")
	}
}

func TestLimitLegacyProbeTargetsPrefersNetworkPaths(t *testing.T) {
	targets := make([]probeTarget, 0, maxLegacyProbeTargets+2)
	for i := 0; i < maxLegacyProbeTargets; i++ {
		targets = append(targets, probeTarget{name: fmt.Sprintf("unrelated_%03d", i), skbPosition: 1})
	}
	targets = append(targets,
		probeTarget{name: "ip_rcv", skbPosition: 1},
		probeTarget{name: "kfree_skb_reason", skbPosition: 1},
	)

	limited, omitted := limitLegacyProbeTargets(targets)
	if omitted != 2 || len(limited) != maxLegacyProbeTargets {
		t.Fatalf("limited=%d omitted=%d", len(limited), omitted)
	}
	names := make(map[string]bool, len(limited))
	for _, target := range limited {
		names[target.name] = true
	}
	if !names["ip_rcv"] || !names["kfree_skb_reason"] {
		t.Fatalf("network targets were not preferred: %v", names)
	}
}
