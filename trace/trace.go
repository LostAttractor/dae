//go:build trace && (amd64 || arm64 || riscv64 || loong64 || ppc64 || ppc64le)

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package trace

import (
	"bytes"
	"cmp"
	"container/list"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/daeuniverse/dae/common/consts"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	log "github.com/sirupsen/logrus"
)

//go:generate go run -mod=mod github.com/cilium/ebpf/cmd/bpf2go -cc "$BPF_CLANG" "$BPF_STRIP_FLAG" -cflags "$BPF_CFLAGS -mcpu=v3" -tags trace -target "$BPF_TRACE_TARGET" -type event bpf kern/trace.c -- -I./headers

var nativeEndian binary.ByteOrder

func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		panic("Could not determine native endianness.")
	}
}

type traceEvent struct {
	Pc         uint64
	Skb        uint64
	Generation uint64
	Sequence   uint32
	DropReason uint32
	Flags      uint32
	Mark       uint32
	Netns      uint32
	Ifindex    uint32
	Pid        uint32
	Ifname     [16]uint8
	Pname      [32]uint8
	Saddr      [16]byte
	Daddr      [16]byte
	Sport      uint16
	Dport      uint16
	L3Proto    uint16
	L4Proto    uint8
	TcpFlags   uint8
	PayloadLen uint16
}

type traceObjects struct {
	collection *ebpf.Collection

	skbPrograms [2][5]*ebpf.Program
	consumeSkb  *ebpf.Program
	kfreeSkb    [2]*ebpf.Program
	lifetimeEnd *ebpf.Program
	groEntry    [2]*ebpf.Program
	groExit     [2]*ebpf.Program

	control *ebpf.Map
	events  *ebpf.Map
	runtime *ebpf.Map
}

func (o *traceObjects) Close() error {
	o.collection.Close()
	return nil
}

const (
	eventFlagTerminal   = uint32(1 << 0)
	eventFlagDrop       = uint32(1 << 1)
	eventFlagDropReason = uint32(1 << 2)
	eventFlagTupleValid = uint32(1 << 3)
	eventFlagConsume    = uint32(1 << 4)

	maxPendingTraces  = 1024
	maxEventsPerTrace = 128

	singleProbeProgram = 0
	multiProbeProgram  = 1
	legacyKfreeProgram = 0
	reasonKfreeProgram = 1
)

type pendingTrace struct {
	events              []traceEvent
	dropSeen            bool
	dropReason          uint32
	dropReasonAvailable bool
	truncated           bool
	position            *list.Element
}

type accumulatedTrace struct {
	events              []traceEvent
	dropSeen            bool
	dropReason          uint32
	dropReasonAvailable bool
	truncated           bool
}

type traceKey struct {
	skb        uint64
	generation uint64
}

type eventAccumulator struct {
	traces map[traceKey]*pendingTrace
	order  *list.List
}

func newEventAccumulator() *eventAccumulator {
	return &eventAccumulator{
		traces: make(map[traceKey]*pendingTrace),
		order:  list.New(),
	}
}

func (a *eventAccumulator) finish(key traceKey, truncated bool) accumulatedTrace {
	trace := a.traces[key]
	delete(a.traces, key)
	a.order.Remove(trace.position)

	slices.SortStableFunc(trace.events, func(a, b traceEvent) int {
		return cmp.Compare(a.Sequence, b.Sequence)
	})
	for i, event := range trace.events {
		if event.Sequence != uint32(i) {
			trace.truncated = true
			break
		}
	}
	return accumulatedTrace{
		events:              trace.events,
		dropSeen:            trace.dropSeen,
		dropReason:          trace.dropReason,
		dropReasonAvailable: trace.dropReasonAvailable,
		truncated:           trace.truncated || truncated,
	}
}

func (a *eventAccumulator) add(event traceEvent) (completed []accumulatedTrace) {
	key := traceKey{skb: event.Skb, generation: event.Generation}
	trace := a.traces[key]
	if trace == nil {
		if len(a.traces) >= maxPendingTraces {
			oldest := a.order.Front().Value.(traceKey)
			completed = append(completed, a.finish(oldest, true))
		}
		trace = &pendingTrace{}
		trace.position = a.order.PushBack(key)
		a.traces[key] = trace
	}

	if len(trace.events) >= maxEventsPerTrace {
		copy(trace.events, trace.events[1:])
		trace.events[len(trace.events)-1] = event
		trace.truncated = true
	} else {
		trace.events = append(trace.events, event)
	}
	trace.dropSeen = trace.dropSeen || event.Flags&eventFlagDrop != 0
	if event.Flags&eventFlagDropReason != 0 {
		trace.dropReason = event.DropReason
		trace.dropReasonAvailable = true
	}
	if event.Flags&eventFlagTerminal != 0 {
		completed = append(completed, a.finish(key, false))
	}
	return completed
}

func (a *eventAccumulator) flush() []accumulatedTrace {
	completed := make([]accumulatedTrace, 0, len(a.traces))
	for a.order.Len() != 0 {
		key := a.order.Front().Value.(traceKey)
		completed = append(completed, a.finish(key, true))
	}
	return completed
}

func shouldWriteTrace(trace accumulatedTrace, dropOnly bool) bool {
	return !dropOnly || trace.dropSeen
}

func writeTraceEvents(writer io.Writer, trace accumulatedTrace, dropReasons map[uint32]string, sessionIncomplete bool) error {
	reasonInEvents := false
	for _, event := range trace.events {
		reasonInEvents = reasonInEvents || event.Flags&eventFlagDropReason != 0
	}
	for i, event := range trace.events {
		if _, err := fmt.Fprintf(writer, "%x gen=%d mark=%x netns=%010d if=%d(%s) proc=%d(%s) ", event.Skb, event.Generation, event.Mark, event.Netns, event.Ifindex, TrimNull(string(event.Ifname[:])), event.Pid, TrimNull(string(event.Pname[:]))); err != nil {
			return err
		}
		if event.Flags&eventFlagTupleValid == 0 {
			if _, err := fmt.Fprint(writer, "tuple=unavailable "); err != nil {
				return err
			}
		} else if event.L3Proto == syscall.ETH_P_IP {
			if _, err := fmt.Fprintf(writer, "%s:%d > %s:%d ", net.IP(event.Saddr[:4]).String(), Ntohs(event.Sport), net.IP(event.Daddr[:4]).String(), Ntohs(event.Dport)); err != nil {
				return err
			}
		} else {
			if _, err := fmt.Fprintf(writer, "[%s]:%d > [%s]:%d ", net.IP(event.Saddr[:]).String(), Ntohs(event.Sport), net.IP(event.Daddr[:]).String(), Ntohs(event.Dport)); err != nil {
				return err
			}
		}
		if event.Flags&eventFlagTupleValid != 0 && event.L4Proto == syscall.IPPROTO_TCP {
			if _, err := fmt.Fprintf(writer, "tcp_flags=%s ", TcpFlags(event.TcpFlags)); err != nil {
				return err
			}
		}
		if event.Flags&eventFlagTupleValid != 0 {
			if _, err := fmt.Fprintf(writer, "payload_len=%d ", event.PayloadLen); err != nil {
				return err
			}
		}
		symbol := "unknown"
		if event.Pc != 0 {
			symbol = NearestSymbol(event.Pc).Name
		} else if event.Flags&eventFlagConsume != 0 {
			symbol = "consume_skb"
		} else if event.Flags&eventFlagTerminal != 0 {
			symbol = "kfree_skb"
		}
		if _, err := fmt.Fprint(writer, symbol); err != nil {
			return err
		}
		reasonAvailable := event.Flags&eventFlagDropReason != 0 ||
			(!reasonInEvents && i == len(trace.events)-1 && trace.dropReasonAvailable)
		if reasonAvailable {
			reasonValue := event.DropReason
			if event.Flags&eventFlagDropReason == 0 {
				reasonValue = trace.dropReason
			}
			reason, ok := dropReasons[reasonValue]
			if !ok {
				reason = fmt.Sprintf("reason=%d", reasonValue)
			}
			if _, err := fmt.Fprintf(writer, "(%s)", reason); err != nil {
				return err
			}
		} else if event.Flags&eventFlagDrop != 0 {
			if _, err := fmt.Fprint(writer, "(drop)"); err != nil {
				return err
			}
		}
		if trace.truncated || sessionIncomplete {
			if _, err := fmt.Fprint(writer, " incomplete"); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(writer); err != nil {
			return err
		}
	}
	return nil
}

func StartTrace(ctx context.Context, ipVersion int, l4ProtoNo uint16, port int, dropOnly bool, outputFile string) (err error) {
	kernelVersion, err := internal.KernelVersion()
	if err != nil {
		return fmt.Errorf("failed to get kernel version: %w", err)
	}
	if requirement := consts.MinimumKernelVersion; kernelVersion.Less(requirement) {
		return fmt.Errorf("your kernel version %v does not satisfy the minimum requirement; expect >=%v",
			kernelVersion.String(),
			requirement.String())
	}
	useKprobeMulti := supportsKprobeMulti(kernelVersion)
	targets, dropReasons, reasonConfig, useKfreeReason, err := searchAvailableTargets()
	if err != nil {
		return
	}
	discoveredTargets := len(targets)

	var multiProgramsLoaded bool
	objs, multiProgramsLoaded, err := rewriteAndLoadBpf(ipVersion, l4ProtoNo, port, reasonConfig, useKprobeMulti)
	if err != nil {
		return
	}
	detacherOwnsObjects := false
	defer func() {
		if !detacherOwnsObjects {
			_ = objs.Close()
		}
	}()
	useKprobeMulti = useKprobeMulti && multiProgramsLoaded
	if err := setTraceProducers(objs.control, true); err != nil {
		return err
	}
	if useKprobeMulti {
		useKprobeMulti = probeKprobeMultiSupport(objs, targets)
	}
	if !useKprobeMulti {
		var omitted int
		targets, omitted = limitLegacyProbeTargets(targets)
		if omitted != 0 {
			log.Warnf("kernel lacks multi-kprobe support; limiting trace to %d probes (%d omitted) for bounded shutdown", len(targets), omitted)
		}
	}
	links, attachedTargets, err := attachBpfToTargets(objs, targets, useKfreeReason, useKprobeMulti)
	if err != nil {
		return
	}
	coverage := probeCoverage{discovered: discoveredTargets, attached: attachedTargets}
	if coverage.incomplete() {
		log.Warnf("trace probe coverage incomplete: attached=%d discovered=%d omitted=%d", coverage.attached, coverage.discovered, coverage.omitted())
	}
	detacher := newProducerDetacher(links, objs.control, objs)
	detacherOwnsObjects = true
	defer func() {
		err = errors.Join(err, detacher.start())
		detacher.releaseObjects()
	}()
	fmt.Printf("\nstart tracing\n")
	if err = handleEvents(ctx, objs, outputFile, dropReasons, dropOnly, coverage, detacher); err != nil {
		return
	}
	return
}

func supportsKprobeMulti(kernelVersion internal.Version) bool {
	return !kernelVersion.Less(internal.Version{5, 18, 0})
}

func rewriteAndLoadBpf(ipVersion int, l4ProtoNo uint16, port int, reasons dropReasonConfig, useKprobeMulti bool) (*traceObjects, bool, error) {
	return loadTraceObjectsWithFallback(useKprobeMulti, func(loadMulti bool) (*traceObjects, error) {
		return loadTraceCollection(ipVersion, l4ProtoNo, port, reasons, loadMulti)
	})
}

func loadTraceObjectsWithFallback(useKprobeMulti bool, load func(bool) (*traceObjects, error)) (*traceObjects, bool, error) {
	objs, err := load(useKprobeMulti)
	if err == nil {
		return objs, useKprobeMulti, nil
	}
	if !useKprobeMulti || !isUnsupportedKprobeMultiLoad(err) {
		return nil, false, err
	}

	log.Debugf("multi-kprobe program loading is unsupported; reloading without multi programs: %v", err)
	objs, fallbackErr := load(false)
	if fallbackErr != nil {
		return nil, false, fmt.Errorf("failed to load BPF without multi-kprobe programs after unsupported attach type: %w", fallbackErr)
	}
	return objs, false, nil
}

func isUnsupportedKprobeMultiLoad(err error) bool {
	if err == nil || !strings.Contains(err.Error(), "kprobe_multi_skb_") {
		return false
	}
	return errors.Is(err, ebpf.ErrNotSupported) ||
		errors.Is(err, syscall.E2BIG) ||
		errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.EOPNOTSUPP)
}

func loadTraceCollection(ipVersion int, l4ProtoNo uint16, port int, reasons dropReasonConfig, useKprobeMulti bool) (_ *traceObjects, err error) {
	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("failed to load BPF: %w", err)
	}
	tracingCfg := spec.Variables["tracing_cfg"]
	if tracingCfg == nil {
		return nil, fmt.Errorf("failed to rewrite constants: missing tracing_cfg in BPF object; run make ebpf to regenerate trace objects")
	}
	if err := tracingCfg.Set(bpfTracingConfig{
		NotDroppedReason: reasons.notDropped,
		ConsumedReason:   reasons.consumed,
		Port:             Htons(uint16(port)),
		L4Proto:          uint16(l4ProtoNo),
		IpVsn:            uint8(ipVersion),
	}); err != nil {
		return nil, fmt.Errorf("failed to rewrite constants: %+v\n", err)
	}
	if !useKprobeMulti {
		for i := 1; i <= 5; i++ {
			delete(spec.Programs, fmt.Sprintf("kprobe_multi_skb_%d", i))
		}
	}
	var opts ebpf.CollectionOptions
	opts.Programs.LogLevel = ebpf.LogLevelInstruction
	collection, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		var (
			ve          *ebpf.VerifierError
			verifierLog string
		)
		if errors.As(err, &ve) {
			verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
		}
		return nil, fmt.Errorf("failed to load BPF: %w\n%s", err, verifierLog)
	}

	objs := &traceObjects{
		collection:  collection,
		consumeSkb:  collection.Programs["raw_tracepoint_consume_skb"],
		lifetimeEnd: collection.Programs["kprobe_skb_lifetime_termination"],
		control:     collection.Maps["control"],
		events:      collection.Maps["events"],
		runtime:     collection.Maps["runtime"],
	}
	for i := range 5 {
		objs.skbPrograms[singleProbeProgram][i] = collection.Programs[fmt.Sprintf("kprobe_skb_%d", i+1)]
		objs.skbPrograms[multiProbeProgram][i] = collection.Programs[fmt.Sprintf("kprobe_multi_skb_%d", i+1)]
	}
	objs.kfreeSkb[legacyKfreeProgram] = collection.Programs["raw_tracepoint_kfree_skb_legacy"]
	objs.kfreeSkb[reasonKfreeProgram] = collection.Programs["raw_tracepoint_kfree_skb_reason"]
	objs.groEntry[0] = collection.Programs["raw_tracepoint_napi_gro_receive_entry"]
	objs.groExit[0] = collection.Programs["raw_tracepoint_napi_gro_receive_exit"]
	objs.groEntry[1] = collection.Programs["raw_tracepoint_napi_gro_frags_entry"]
	objs.groExit[1] = collection.Programs["raw_tracepoint_napi_gro_frags_exit"]
	return objs, nil
}

type probeTarget struct {
	name        string
	skbPosition int
}

const maxLegacyProbeTargets = 64

var legacyProbeKeywords = []string{
	"receive", "rcv", "input", "deliver", "forward", "output", "xmit",
	"queue", "drop", "consume", "free", "netfilter", "nf_", "nft_",
	"tcf_", "sch_", "tproxy",
}

var legacyCriticalProbes = map[string]struct{}{
	"__dev_queue_xmit":         {},
	"__netif_receive_skb":      {},
	"__netif_receive_skb_core": {},
	"br_handle_frame":          {},
	"br_handle_frame_finish":   {},
	"dev_queue_xmit":           {},
	"ip6_finish_output":        {},
	"ip6_forward":              {},
	"ip6_input":                {},
	"ip6_local_out":            {},
	"ip6_output":               {},
	"ip6_xmit":                 {},
	"ip_finish_output":         {},
	"ip_forward":               {},
	"ip_local_deliver":         {},
	"ip_local_out":             {},
	"ip_output":                {},
	"ip_queue_xmit":            {},
	"ip_rcv":                   {},
	"ip_rcv_core":              {},
	"netif_receive_skb":        {},
	"netif_rx":                 {},
	"nf_hook_slow":             {},
	"sch_handle_ingress":       {},
	"tcp_transmit_skb":         {},
	"tcp_v4_rcv":               {},
	"tcp_v6_rcv":               {},
	"tcf_classify":             {},
	"udp_rcv":                  {},
	"udpv6_rcv":                {},
	"ipv6_rcv":                 {},
}

func limitLegacyProbeTargets(targets []probeTarget) ([]probeTarget, int) {
	if len(targets) <= maxLegacyProbeTargets {
		return targets, 0
	}
	limited := append([]probeTarget(nil), targets...)
	slices.SortStableFunc(limited, func(a, b probeTarget) int {
		aPriority := legacyProbePriority(a.name)
		bPriority := legacyProbePriority(b.name)
		if aPriority != bPriority {
			return cmp.Compare(aPriority, bPriority)
		}
		return strings.Compare(a.name, b.name)
	})
	return limited[:maxLegacyProbeTargets], len(targets) - maxLegacyProbeTargets
}

func legacyProbePriority(name string) int {
	if _, critical := legacyCriticalProbes[name]; critical {
		return 0
	}
	for _, keyword := range legacyProbeKeywords {
		if strings.Contains(name, keyword) {
			return 1
		}
	}
	return 2
}

type dropReasonConfig struct {
	notDropped uint32
	consumed   uint32
}

const unavailableDropReason = ^uint32(0)

func classifyFunction(fn *btf.Func) (probeTarget, bool) {
	target := probeTarget{name: fn.Name}
	proto, ok := fn.Type.(*btf.FuncProto)
	if !ok {
		return probeTarget{}, false
	}
	for i, param := range proto.Params {
		position := i + 1
		typ := btf.UnderlyingType(param.Type)
		if ptr, ok := typ.(*btf.Pointer); ok {
			if strct, ok := btf.UnderlyingType(ptr.Target).(*btf.Struct); ok && strct.Name == "sk_buff" && target.skbPosition == 0 {
				target.skbPosition = position
			}
		}
	}
	return target, target.name != "" && target.skbPosition > 0 && target.skbPosition <= 5
}

func typeHasDropReason(typ btf.Type) bool {
	ptr, ok := btf.UnderlyingType(typ).(*btf.Pointer)
	if !ok {
		return false
	}
	proto, ok := btf.UnderlyingType(ptr.Target).(*btf.FuncProto)
	if !ok {
		return false
	}
	for _, param := range proto.Params {
		if enum, ok := btf.UnderlyingType(param.Type).(*btf.Enum); ok && enum.Name == "skb_drop_reason" {
			return true
		}
	}
	return false
}

func canClassifyKfreeReason(traceType btf.Type, config dropReasonConfig) bool {
	return typeHasDropReason(traceType) && config.notDropped != unavailableDropReason
}

func searchAvailableTargets() (targets []probeTarget, dropReasons map[uint32]string, reasonConfig dropReasonConfig, useKfreeReason bool, err error) {
	targetsByName := make(map[string]probeTarget)
	reasonConfig.notDropped = unavailableDropReason
	reasonConfig.consumed = unavailableDropReason

	btfSpec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, nil, reasonConfig, false, fmt.Errorf("failed to load kernel BTF: %+v\n", err)
	}

	if dropReasons, reasonConfig, err = getDropReasons(btfSpec); err != nil {
		return
	}
	traceType, typeErr := btfSpec.AnyTypeByName("btf_trace_kfree_skb")
	if typeErr != nil {
		return nil, nil, reasonConfig, false, fmt.Errorf("failed to inspect kfree_skb raw tracepoint ABI: %w", typeErr)
	}
	// Linux 5.17 has the reason-aware tracepoint ABI but no
	// SKB_NOT_DROPPED_YET sentinel. Reading only the first two arguments is ABI
	// safe and preserves the legacy behavior of treating kfree_skb as a drop.
	useKfreeReason = canClassifyKfreeReason(traceType, reasonConfig)

	for typ, err := range btfSpec.All() {
		if err != nil {
			continue
		}
		fn, ok := typ.(*btf.Func)
		if !ok {
			continue
		}

		target, ok := classifyFunction(fn)
		if !ok || target.name == "kfree_skbmem" {
			continue
		}
		if len(kprobeSymbols) != 0 {
			if _, exists := kprobeSymbols[target.name]; !exists {
				continue
			}
		} else if len(kallsymsByName) != 0 {
			symbol, exists := kallsymsByName[target.name]
			if !exists || !strings.ContainsAny(symbol.Type, "TtWw") {
				continue
			}
		}
		targetsByName[target.name] = target
	}

	targets = make([]probeTarget, 0, len(targetsByName))
	for _, target := range targetsByName {
		targets = append(targets, target)
	}
	slices.SortFunc(targets, func(a, b probeTarget) int {
		switch {
		case a.name < b.name:
			return -1
		case a.name > b.name:
			return 1
		default:
			return 0
		}
	})
	return targets, dropReasons, reasonConfig, useKfreeReason, nil
}

func getDropReasons(spec *btf.Spec) (map[uint32]string, dropReasonConfig, error) {
	var dropReasonsEnum *btf.Enum
	if err := spec.TypeByName("skb_drop_reason", &dropReasonsEnum); err != nil {
		if errors.Is(err, btf.ErrNotFound) {
			return nil, dropReasonConfig{notDropped: unavailableDropReason, consumed: unavailableDropReason}, nil
		}
		return nil, dropReasonConfig{}, fmt.Errorf("failed to find 'skb_drop_reason' enum: %v", err)
	}
	return dropReasonsFromEnum(dropReasonsEnum)
}

func dropReasonsFromEnum(dropReasonsEnum *btf.Enum) (map[uint32]string, dropReasonConfig, error) {
	config := dropReasonConfig{notDropped: unavailableDropReason, consumed: unavailableDropReason}
	ret := map[uint32]string{}
	for _, val := range dropReasonsEnum.Values {
		value := uint32(val.Value)
		ret[value] = val.Name
		switch val.Name {
		case "SKB_NOT_DROPPED_YET":
			config.notDropped = value
		case "SKB_CONSUMED":
			config.consumed = value
		}
	}

	return ret, config, nil
}

type traceEventReader interface {
	Read() (ringbuf.Record, error)
	Flush() error
}

type traceRuntime interface {
	Lookup(key, valueOut any) error
}

const (
	producerQuiesceTimeout = 2 * time.Second
	producerQuiescePoll    = 2 * time.Millisecond
)

func waitForTraceProducers(runtime traceRuntime, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		var state bpfRuntimeState
		key := uint32(0)
		if err := runtime.Lookup(&key, &state); err != nil {
			return fmt.Errorf("read active trace producers: %w", err)
		}
		if state.ActiveProducers == 0 {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("timed out after %s waiting for %d active trace producer(s)", timeout, state.ActiveProducers)
		}
		time.Sleep(producerQuiescePoll)
	}
}

func handleEvents(ctx context.Context, objs *traceObjects, outputFile string, dropReasons map[uint32]string, dropOnly bool, coverage probeCoverage, detacher *producerDetacher) (err error) {
	writer, err := os.Create(outputFile)
	if err != nil {
		return errors.Join(err, detacher.start())
	}

	eventsReader, err := ringbuf.NewReader(objs.events)
	if err != nil {
		return errors.Join(
			fmt.Errorf("failed to create ringbuf reader: %+v", err),
			detacher.start(),
			writer.Close(),
		)
	}
	defer func() {
		err = errors.Join(err, detacher.start(), eventsReader.Close(), writer.Close())
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := setTraceProducers(objs.control, false); err != nil {
		return err
	}

	return readTraceEvents(ctx, objs.runtime, eventsReader, writer, dropReasons, dropOnly, coverage, detacher)
}

func readTraceEvents(ctx context.Context, runtime traceRuntime, eventsReader traceEventReader, writer io.Writer, dropReasons map[uint32]string, dropOnly bool, coverage probeCoverage, detacher *producerDetacher) (err error) {
	shutdownDone := make(chan struct{})
	var shutdownOnce sync.Once
	var shutdownErr error
	shutdown := func() error {
		shutdownOnce.Do(func() {
			shutdownErr = detacher.start()
			if shutdownErr != nil {
				if detachErr := detacher.waitDetached(); detachErr != nil {
					shutdownErr = errors.Join(shutdownErr, fmt.Errorf("detach trace probes after producer stop failure: %w", detachErr))
				}
			}
			if waitErr := waitForTraceProducers(runtime, producerQuiesceTimeout); waitErr != nil {
				shutdownErr = errors.Join(shutdownErr, waitErr)
			}
			if flushErr := eventsReader.Flush(); flushErr != nil {
				shutdownErr = errors.Join(shutdownErr, fmt.Errorf("flush ring buffer: %w", flushErr))
			}
			close(shutdownDone)
		})
		<-shutdownDone
		return shutdownErr
	}
	watcherDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = shutdown()
		case <-watcherDone:
		}
	}()
	defer func() {
		close(watcherDone)
		err = errors.Join(err, shutdown())
	}()

	sessionIncomplete := coverage.incomplete()
	if sessionIncomplete {
		if _, err := fmt.Fprintf(writer, "# trace incomplete: probe coverage attached=%d discovered=%d omitted=%d\n", coverage.attached, coverage.discovered, coverage.omitted()); err != nil {
			return err
		}
	}
	accumulator := newEventAccumulator()
	writeCompleted := func(completed []accumulatedTrace) error {
		for _, trace := range completed {
			if !shouldWriteTrace(trace, dropOnly) {
				continue
			}
			if err := writeTraceEvents(writer, trace, dropReasons, sessionIncomplete); err != nil {
				return err
			}
		}
		return nil
	}
	var decodeLoss uint64
	finish := func() error {
		if err := writeCompleted(accumulator.flush()); err != nil {
			return err
		}
		var runtimeState bpfRuntimeState
		key := uint32(0)
		if err := runtime.Lookup(&key, &runtimeState); err != nil {
			return fmt.Errorf("read trace runtime counters: %w", err)
		}
		if runtimeState.RingLost != 0 {
			if _, err := fmt.Fprintf(writer, "# trace incomplete: %d event(s) lost in the BPF ring buffer\n", runtimeState.RingLost); err != nil {
				return err
			}
			log.Warnf("trace incomplete: %d event(s) lost in the BPF ring buffer", runtimeState.RingLost)
		}
		if runtimeState.AdmissionFailures != 0 {
			if _, err := fmt.Fprintf(writer, "# trace incomplete: %d trace admission(s) failed\n", runtimeState.AdmissionFailures); err != nil {
				return err
			}
			log.Warnf("trace incomplete: %d trace admission(s) failed", runtimeState.AdmissionFailures)
		}
		if runtimeState.GenerationFailures != 0 {
			if _, err := fmt.Fprintf(writer, "# trace incomplete: %d trace generation allocation(s) failed\n", runtimeState.GenerationFailures); err != nil {
				return err
			}
			log.Warnf("trace incomplete: %d trace generation allocation(s) failed", runtimeState.GenerationFailures)
		}
		if runtimeState.AdmissionRaces != 0 {
			if _, err := fmt.Fprintf(writer, "# trace: recovered %d concurrent admission race(s)\n", runtimeState.AdmissionRaces); err != nil {
				return err
			}
		}
		if runtimeState.ActiveProducers != 0 {
			if _, err := fmt.Fprintf(writer, "# trace incomplete: %d producer(s) still active at shutdown\n", runtimeState.ActiveProducers); err != nil {
				return err
			}
		}
		if decodeLoss != 0 {
			if _, err := fmt.Fprintf(writer, "# trace incomplete: %d malformed ring event(s) could not be decoded\n", decodeLoss); err != nil {
				return err
			}
		}
		if shutdownErr != nil {
			if _, err := fmt.Fprintf(writer, "# trace incomplete: shutdown did not quiesce cleanly: %v\n", shutdownErr); err != nil {
				return err
			}
		}
		return nil
	}

	for {
		rec, err := eventsReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrFlushed) {
				_ = shutdown()
				return finish()
			}
			_ = shutdown()
			return errors.Join(finish(), fmt.Errorf("read ring buffer: %w", err))
		}

		var event traceEvent
		if err = binary.Read(bytes.NewBuffer(rec.RawSample), nativeEndian, &event); err != nil {
			log.Debugf("failed to parse ringbuf event: %+v", err)
			decodeLoss++
			continue
		}
		if err := writeCompleted(accumulator.add(event)); err != nil {
			return err
		}
	}
}
