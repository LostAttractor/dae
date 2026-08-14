//go:build trace

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package trace

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/daeuniverse/dae/common/consts"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	log "github.com/sirupsen/logrus"
)

//go:generate go run -mod=mod github.com/cilium/ebpf/cmd/bpf2go -cc "$BPF_CLANG" "$BPF_STRIP_FLAG" -cflags "$BPF_CFLAGS" -tags trace -target "$BPF_TRACE_TARGET" -type event bpf kern/trace.c -- -I./headers

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
	Pc          uint64
	Skb         uint64
	SecondParam uint64
	Mark        uint32
	Netns       uint32
	Ifindex     uint32
	Pid         uint32
	Ifname      [16]uint8
	Pname       [32]uint8
	Saddr       [16]byte
	Daddr       [16]byte
	Sport       uint16
	Dport       uint16
	L3Proto     uint16
	L4Proto     uint8
	TcpFlags    uint8
	PayloadLen  uint16
}

type eventAccumulator struct {
	events  map[uint64][]traceEvent
	symbols map[uint64][]string
}

func newEventAccumulator() *eventAccumulator {
	return &eventAccumulator{
		events:  make(map[uint64][]traceEvent),
		symbols: make(map[uint64][]string),
	}
}

func (a *eventAccumulator) add(event traceEvent, symbol string, dropOnly bool) ([]traceEvent, bool) {
	a.events[event.Skb] = append(a.events[event.Skb], event)
	a.symbols[event.Skb] = append(a.symbols[event.Skb], symbol)
	if symbol != "__kfree_skb" && symbol != "kfree_skbmem" {
		return nil, false
	}

	events := a.events[event.Skb]
	shouldWrite := !dropOnly || slices.Contains(a.symbols[event.Skb], "kfree_skb_reason")
	delete(a.events, event.Skb)
	delete(a.symbols, event.Skb)
	return events, shouldWrite
}

func writeTraceEvents(writer io.Writer, events []traceEvent, kfreeSkbReasons map[uint64]string, complete bool) error {
	for _, event := range events {
		if _, err := fmt.Fprintf(writer, "%x mark=%x netns=%010d if=%d(%s) proc=%d(%s) ", event.Skb, event.Mark, event.Netns, event.Ifindex, TrimNull(string(event.Ifname[:])), event.Pid, TrimNull(string(event.Pname[:]))); err != nil {
			return err
		}
		if event.L3Proto == syscall.ETH_P_IP {
			if _, err := fmt.Fprintf(writer, "%s:%d > %s:%d ", net.IP(event.Saddr[:4]).String(), Ntohs(event.Sport), net.IP(event.Daddr[:4]).String(), Ntohs(event.Dport)); err != nil {
				return err
			}
		} else {
			if _, err := fmt.Fprintf(writer, "[%s]:%d > [%s]:%d ", net.IP(event.Saddr[:]).String(), Ntohs(event.Sport), net.IP(event.Daddr[:]).String(), Ntohs(event.Dport)); err != nil {
				return err
			}
		}
		if event.L4Proto == syscall.IPPROTO_TCP {
			if _, err := fmt.Fprintf(writer, "tcp_flags=%s ", TcpFlags(event.TcpFlags)); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(writer, "payload_len=%d ", event.PayloadLen); err != nil {
			return err
		}
		sym := NearestSymbol(event.Pc)
		if _, err := fmt.Fprint(writer, sym.Name); err != nil {
			return err
		}
		if sym.Name == "kfree_skb_reason" {
			if _, err := fmt.Fprintf(writer, "(%s)", kfreeSkbReasons[event.SecondParam]); err != nil {
				return err
			}
		}
		if !complete {
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
	objs, err := rewriteAndLoadBpf(ipVersion, l4ProtoNo, port)
	if err != nil {
		return
	}
	defer objs.Close()

	targets, kfreeSkbReasons, err := searchAvailableTargets()
	if err != nil {
		return
	}

	links, err := attachBpfToTargets(objs, targets)
	if err != nil {
		return
	}
	defer func() {
		i := 0
		fmt.Printf("\n")
		for _, link := range links {
			i++
			fmt.Printf("detaching kprobes: %04d/%04d\r", i, len(links))
			link.Close()
		}
		fmt.Printf("\n")
	}()

	fmt.Printf("\nstart tracing\n")
	if err = handleEvents(ctx, objs, outputFile, kfreeSkbReasons, dropOnly); err != nil {
		return
	}
	return
}

func rewriteAndLoadBpf(ipVersion int, l4ProtoNo uint16, port int) (_ *bpfObjects, err error) {
	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("failed to load BPF: %+v\n", err)
	}
	tracingCfg := spec.Variables["tracing_cfg"]
	if tracingCfg == nil {
		return nil, fmt.Errorf("failed to rewrite constants: missing tracing_cfg in BPF object; run make ebpf to regenerate trace objects")
	}
	if err := tracingCfg.Set(struct {
		port      uint16
		l4Proto   uint16
		ipVersion uint8
		pad       uint8
	}{
		port:      Htons(uint16(port)),
		l4Proto:   uint16(l4ProtoNo),
		ipVersion: uint8(ipVersion),
		pad:       0,
	}); err != nil {
		return nil, fmt.Errorf("failed to rewrite constants: %+v\n", err)
	}
	var opts ebpf.CollectionOptions
	opts.Programs.LogLevel = ebpf.LogLevelInstruction
	objs := bpfObjects{}
	if err := spec.LoadAndAssign(&objs, &opts); err != nil {
		var (
			ve          *ebpf.VerifierError
			verifierLog string
		)
		if errors.As(err, &ve) {
			verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
		}
		return nil, fmt.Errorf("failed to load BPF: %+v\n%s", err, verifierLog)
	}

	return &objs, nil
}

func searchAvailableTargets() (targets map[string]int, kfreeSkbReasons map[uint64]string, err error) {
	targets = map[string]int{}

	btfSpec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load kernel BTF: %+v\n", err)
	}

	if kfreeSkbReasons, err = getKFreeSKBReasons(btfSpec); err != nil {
		return
	}

	for typ, err := range btfSpec.All() {
		if err != nil {
			continue
		}
		fn, ok := typ.(*btf.Func)
		if !ok {
			continue
		}

		fnName := string(fn.Name)

		fnProto := fn.Type.(*btf.FuncProto)
		i := 1
		for _, p := range fnProto.Params {
			if ptr, ok := p.Type.(*btf.Pointer); ok {
				if strct, ok := ptr.Target.(*btf.Struct); ok {
					if strct.Name == "sk_buff" && i <= 5 {
						name := fnName
						targets[name] = i
						continue
					}
				}
			}
			i += 1
		}
	}

	return targets, kfreeSkbReasons, nil
}

func getKFreeSKBReasons(spec *btf.Spec) (map[uint64]string, error) {
	if _, err := spec.AnyTypeByName("kfree_skb_reason"); err != nil {
		// Kernel is too old to have kfree_skb_reason
		return nil, nil
	}

	var dropReasonsEnum *btf.Enum
	if err := spec.TypeByName("skb_drop_reason", &dropReasonsEnum); err != nil {
		return nil, fmt.Errorf("failed to find 'skb_drop_reason' enum: %v", err)
	}

	ret := map[uint64]string{}
	for _, val := range dropReasonsEnum.Values {
		ret[uint64(val.Value)] = val.Name

	}

	return ret, nil
}

func attachBpfToTargets(objs *bpfObjects, targets map[string]int) (links []link.Link, err error) {
	kp, err := link.Kprobe("kfree_skbmem", objs.KprobeSkbLifetimeTermination, nil)
	if err != nil {
		log.Warnf("failed to attach kprobe to kfree_skbmem: %+v\n", err)
	} else {
		links = append(links, kp)
	}

	i := 0
	attachedTargets := 0
	for fn, pos := range targets {
		i++
		fmt.Printf("attaching kprobes: %04d/%04d\r", i, len(targets))
		var kp link.Link
		switch pos {
		case 1:
			kp, err = link.Kprobe(fn, objs.KprobeSkb1, nil)
		case 2:
			kp, err = link.Kprobe(fn, objs.KprobeSkb2, nil)
		case 3:
			kp, err = link.Kprobe(fn, objs.KprobeSkb3, nil)
		case 4:
			kp, err = link.Kprobe(fn, objs.KprobeSkb4, nil)
		case 5:
			kp, err = link.Kprobe(fn, objs.KprobeSkb5, nil)
		}
		if err != nil {
			log.Debugf("failed to attach kprobe to %s: %+v\n", fn, err)
			continue
		}
		links = append(links, kp)
		attachedTargets++
	}
	if attachedTargets == 0 {
		for _, l := range links {
			_ = l.Close()
		}
		return nil, fmt.Errorf("failed to attach kprobes to any target")
	}
	return links, nil
}

func handleEvents(ctx context.Context, objs *bpfObjects, outputFile string, kfreeSkbReasons map[uint64]string, dropOnly bool) (err error) {
	writer, err := os.Create(outputFile)
	if err != nil {
		return
	}
	defer func() {
		if closeErr := writer.Close(); err == nil {
			err = closeErr
		}
	}()

	eventsReader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("failed to create ringbuf reader: %+v\n", err)
	}
	defer func() { _ = eventsReader.Close() }()

	stopFlush := make(chan struct{})
	defer close(stopFlush)
	go func() {
		select {
		case <-ctx.Done():
			if err := eventsReader.Flush(); err != nil {
				_ = eventsReader.Close()
			}
		case <-stopFlush:
		}
	}()

	accumulator := newEventAccumulator()
	flushPendingEvents := func() error {
		if dropOnly {
			return nil
		}
		for _, events := range accumulator.events {
			if err := writeTraceEvents(writer, events, kfreeSkbReasons, false); err != nil {
				return err
			}
		}
		return nil
	}
	for {
		rec, err := eventsReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrFlushed) || errors.Is(err, ringbuf.ErrClosed) {
				return flushPendingEvents()
			}
			if ctx.Err() != nil {
				return flushPendingEvents()
			}
			log.Debugf("failed to read ringbuf: %+v", err)
			continue
		}

		var event traceEvent
		if err = binary.Read(bytes.NewBuffer(rec.RawSample), nativeEndian, &event); err != nil {
			log.Debugf("failed to parse ringbuf event: %+v", err)
			continue
		}
		sym := NearestSymbol(event.Pc)
		events, shouldWrite := accumulator.add(event, sym.Name, dropOnly)
		if shouldWrite {
			if err := writeTraceEvents(writer, events, kfreeSkbReasons, true); err != nil {
				return err
			}
		}
	}
}
