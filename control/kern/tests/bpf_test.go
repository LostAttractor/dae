//go:build linux && dae_bpf_tests

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package tests

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

//go:generate go run -mod=mod github.com/cilium/ebpf/cmd/bpf2go -cc "$BPF_CLANG" "$BPF_STRIP_FLAG" -cflags "$BPF_CFLAGS" -tags "linux,dae_bpf_tests" -target "$BPF_TARGET" bpftest ./bpf_test.c -- -I../headers -I.

type programSet struct {
	id     string
	pktgen *ebpf.Program
	setup  *ebpf.Program
	check  *ebpf.Program
}

type testDaeParam struct {
	ControlPlanePid      uint32
	Dae0Ifindex          uint32
	Dae0peerIfindex      uint32
	Dae0peerMac          [6]uint8
	HasBpfGetCurrentTask uint8
	Padding              uint8
	SoMarkFromDae        uint32
}

func runBpfProgram(prog *ebpf.Program, data, ctx []byte) (statusCode uint32, dataOut, ctxOut []byte, err error) {
	dataOut = make([]byte, len(data))
	if len(dataOut) > 0 {
		// See comments at https://github.com/cilium/ebpf/blob/20c4d8896bdde990ce6b80d59a4262aa3ccb891d/prog.go#L563-L567
		dataOut = make([]byte, len(data)+256+2)
	}
	ctxOut = make([]byte, len(ctx))
	opts := &ebpf.RunOptions{
		Data:       data,
		DataOut:    dataOut,
		Context:    ctx,
		ContextOut: ctxOut,
		Repeat:     1,
	}
	ret, err := prog.Run(opts)
	return ret, opts.DataOut, ctxOut, err
}

func loadTestObjects(t testing.TB) (*bpftestObjects, error) {
	t.Helper()
	obj := &bpftestObjects{}
	pinPath := "/sys/fs/bpf/dae"
	if err := os.MkdirAll(pinPath, 0755); err != nil && !os.IsExist(err) {
		return nil, err
	}

	spec, err := loadBpftest()
	if err != nil {
		return nil, err
	}
	param, ok := spec.Variables["PARAM"]
	if !ok {
		return nil, errors.New("missing PARAM constant")
	}
	if err := param.Set(testDaeParam{
		ControlPlanePid: uint32(os.Getpid()),
		SoMarkFromDae:   0x100,
	}); err != nil {
		return nil, err
	}
	// Kernel tests must not reuse or replace the daemon's persistent routing state.
	spec.Maps["routing_tuples_map"].Pinning = ebpf.PinNone
	if err := spec.LoadAndAssign(obj,
		&ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{
				PinPath: pinPath,
			},
			Programs: ebpf.ProgramOptions{},
		},
	); err != nil {
		var (
			ve          *ebpf.VerifierError
			verifierLog string
		)
		if errors.As(err, &ve) {
			verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
		}
		return nil, fmt.Errorf("failed to load objects: %s%w", verifierLog, err)
	}

	if err := obj.LpmArrayMap.Update(uint32(0), obj.UnusedLpmType, ebpf.UpdateAny); err != nil {
		obj.Close()
		return nil, fmt.Errorf("update LpmArrayMap: %w", err)
	}
	t.Cleanup(func() { obj.Close() })
	return obj, nil
}

func collectPrograms(t *testing.T) (progset []programSet, err error) {
	obj, err := loadTestObjects(t)
	if err != nil {
		return nil, err
	}

	v := reflect.ValueOf(obj.bpftestPrograms)
	typeOfV := v.Type()
	for i := 0; i < v.NumField(); i++ {
		progname := typeOfV.Field(i).Name
		if strings.HasPrefix(progname, "Testsetup") {
			progid := strings.TrimPrefix(progname, "Testsetup")
			progset = append(progset, programSet{
				id:     progid,
				pktgen: v.FieldByName("Testpktgen" + progid).Interface().(*ebpf.Program),
				setup:  v.FieldByName("Testsetup" + progid).Interface().(*ebpf.Program),
				check:  v.FieldByName("Testcheck" + progid).Interface().(*ebpf.Program),
			})
		}
	}
	return
}

func benchmarkUDPRoutingCache(b *testing.B, obj *bpftestObjects, rules int, hit bool) {
	b.Helper()
	const (
		matchTypePort     = 3
		matchTypeFallback = 11
		outbound          = 2
	)

	miss := bpftestMatchSet{Type: matchTypePort, Outbound: outbound}
	binary.NativeEndian.PutUint16(miss.Value[0:2], 1)
	binary.NativeEndian.PutUint16(miss.Value[2:4], 1)
	for i := 0; i < rules-1; i++ {
		if err := obj.RoutingMap.Update(uint32(i), &miss, ebpf.UpdateAny); err != nil {
			b.Fatal(err)
		}
	}
	fallback := bpftestMatchSet{Type: matchTypeFallback, Outbound: outbound}
	if err := obj.RoutingMap.Update(uint32(rules-1), &fallback, ebpf.UpdateAny); err != nil {
		b.Fatal(err)
	}
	connectivityKey := bpftestOutboundConnectivityQuery{
		Outbound: outbound, L4proto: unix.IPPROTO_UDP, Ipversion: 4,
	}
	connectivityAlive := uint32(0)
	if err := obj.OutboundConnectivityMap.Update(&connectivityKey, &connectivityAlive, ebpf.UpdateAny); err != nil {
		b.Fatal(err)
	}

	data := make([]byte, 4096-256-320)
	ctx := make([]byte, 256)
	status, packet, packetCtx, err := runBpfProgram(obj.TestpktgenUdpRouteCacheMiss, data, ctx)
	if err != nil || status != 0 {
		b.Fatalf("generate benchmark packet: status %d, error %v", status, err)
	}
	handoffKey := bpftestTuplesKey{
		Sport: nativeUint16(20001), Dport: nativeUint16(443),
		L4proto: unix.IPPROTO_UDP,
	}
	handoffKey.Sip.U6Addr8 = netip.MustParseAddr("192.168.1.1").As16()
	handoffKey.Dip.U6Addr8 = netip.MustParseAddr("1.1.1.1").As16()
	if err := clearUDPRoutingCache(obj.UdpRoutingCacheMap); err != nil {
		b.Fatal(err)
	}
	_ = obj.RoutingTuplesMap.Delete(&handoffKey)
	status, _, _, err = runBpfProgram(obj.TproxyWanEgressL2, packet, packetCtx)
	if err != nil || status != 7 {
		b.Fatalf("prime benchmark cache: status %d, error %v", status, err)
	}
	var cacheKey bpftestUdpRoutingCacheKey
	var cacheValue bpftestUdpRoutingCacheValue
	iter := obj.UdpRoutingCacheMap.Iterate()
	if !iter.Next(&cacheKey, &cacheValue) {
		b.Fatalf("prime benchmark cache: %v", iter.Err())
	}
	if hit {
		cacheValue.CachedUntil = math.MaxUint64
		if err := obj.UdpRoutingCacheMap.Update(&cacheKey, &cacheValue, ebpf.UpdateAny); err != nil {
			b.Fatal(err)
		}
	} else {
		if err := obj.UdpRoutingCacheMap.Delete(&cacheKey); err != nil {
			b.Fatal(err)
		}
		_ = obj.RoutingTuplesMap.Delete(&handoffKey)
	}
	dataOut := make([]byte, len(packet)+256+2)
	ctxOut := make([]byte, len(packetCtx))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if !hit {
			b.StopTimer()
			if err := obj.UdpRoutingCacheMap.Delete(&cacheKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				b.Fatal(err)
			}
			if err := obj.RoutingTuplesMap.Delete(&handoffKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				b.Fatal(err)
			}
			b.StartTimer()
		}
		opts := &ebpf.RunOptions{
			Data:       packet,
			DataOut:    dataOut,
			Context:    packetCtx,
			ContextOut: ctxOut,
			Repeat:     1,
		}
		status, err := obj.TproxyWanEgressL2.Run(opts)
		if err != nil || status != 7 {
			b.Fatalf("run benchmark packet: status %d, error %v", status, err)
		}
	}
}

func clearUDPRoutingCache(m *ebpf.Map) error {
	var key bpftestUdpRoutingCacheKey
	var value bpftestUdpRoutingCacheValue
	var keys []bpftestUdpRoutingCacheKey
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for i := range keys {
		if err := m.Delete(&keys[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}

func nativeUint16(value uint16) uint16 {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	return nl.NativeEndian().Uint16(encoded[:])
}

func BenchmarkUDPRoutingCache(b *testing.B) {
	obj, err := loadTestObjects(b)
	if err != nil {
		b.Fatal(err)
	}
	for _, rules := range []int{16, 128, 512, 1024} {
		b.Run(fmt.Sprintf("miss/rules=%d", rules), func(b *testing.B) {
			benchmarkUDPRoutingCache(b, obj, rules, false)
		})
		b.Run(fmt.Sprintf("hit/rules=%d", rules), func(b *testing.B) {
			benchmarkUDPRoutingCache(b, obj, rules, true)
		})
	}
}

func BenchmarkPacketParser(b *testing.B) {
	obj, err := loadTestObjects(b)
	if err != nil {
		b.Fatal(err)
	}
	const (
		repeat = 10000
	)

	for _, tc := range []struct {
		name     string
		pktgen   *ebpf.Program
		expected uint32
	}{
		{name: "ipv4-udp", pktgen: obj.TestpktgenUdpRouteCacheMiss},
		{name: "ipv6-udp", pktgen: obj.TestpktgenParserIpv6Udp},
		{name: "ipv6-ah", pktgen: obj.TestpktgenIpv6AhUdpUnfragmented, expected: 1},
		{name: "ipv6-max-extensions", pktgen: obj.TestpktgenIpv6MaxExtensions},
		{name: "ipv6-first-fragment", pktgen: obj.TestpktgenIpv6FirstUdpFragmentRouting},
		{name: "ipv6-nonfirst-fragment", pktgen: obj.TestpktgenIpv6NonfirstUdpFragment},
	} {
		b.Run(tc.name, func(b *testing.B) {
			data := make([]byte, 4096-256-320)
			ctx := make([]byte, 256)
			status, packet, _, err := runBpfProgram(tc.pktgen, data, ctx)
			if err != nil || status != 0 {
				b.Fatalf("generate packet: status %d, error %v", status, err)
			}
			var runtimeTotal time.Duration
			b.ResetTimer()
			for range b.N {
				status, runtimePerRun, err := obj.TestParserBenchmark.Benchmark(packet, repeat, b.ResetTimer)
				if err != nil || status != tc.expected {
					b.Fatalf("benchmark packet: status %d, error %v", status, err)
				}
				runtimeTotal += runtimePerRun
			}
			b.ReportMetric(float64(runtimeTotal.Nanoseconds())/float64(max(b.N, 1)), "bpf-ns/op")
		})
	}
}

func consumeBpfDebugLog(t *testing.T) {
	readBpfDebugLog(t)
}

func printBpfDebugLog(t *testing.T) {
	fmt.Print(readBpfDebugLog(t))
}

func readBpfDebugLog(t *testing.T) string {
	const maxDebugLogSize = 1024 * 1024

	file, err := os.OpenFile("/sys/kernel/tracing/trace_pipe", os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatalf("Failed to open trace_pipe: %v", err)
	}
	defer file.Close()

	buffer := make([]byte, 1024*64)
	var logs strings.Builder
	for logs.Len() < maxDebugLogSize {
		n, err := unix.Read(int(file.Fd()), buffer)
		if n > 0 {
			remaining := maxDebugLogSize - logs.Len()
			if n > remaining {
				n = remaining
			}
			logs.Write(buffer[:n])
		}
		if errors.Is(err, unix.EAGAIN) {
			break
		}
		if err != nil {
			t.Fatalf("Failed to read from trace_pipe: %v", err)
		}
		if n == 0 {
			break
		}
	}

	return logs.String()
}

func Test(t *testing.T) {
	progsets, err := collectPrograms(t)
	if err != nil {
		t.Fatalf("error while collecting programs: %s", err)
	}

	for _, progset := range progsets {
		t.Logf("Running test: %s\n", progset.id)
		// create ctx with the max allowed size(4k - head room - tailroom)
		data := make([]byte, 4096-256-320)

		// sizeof(struct __sk_buff) < 256, let's make it 256
		ctx := make([]byte, 256)

		statusCode, data, ctx, err := runBpfProgram(progset.pktgen, data, ctx)
		if err != nil {
			t.Fatalf("error while running pktgen prog: %s", err)
		}
		if statusCode != 0 {
			printBpfDebugLog(t)
			t.Fatalf("error while running pktgen program: unexpected status code: %d", statusCode)
		}
		statusCode, data, ctx, err = runBpfProgram(progset.setup, data, ctx)
		if err != nil {
			printBpfDebugLog(t)
			t.Fatalf("error while running setup prog: %s", err)
		}

		status := make([]byte, 4)
		nl.NativeEndian().PutUint32(status, statusCode)
		data = append(status, data...)

		statusCode, data, ctx, err = runBpfProgram(progset.check, data, ctx)
		if err != nil {
			t.Fatalf("error while running check program: %+v", err)
		}
		if statusCode != 0 {
			printBpfDebugLog(t)
			t.Fatalf("error while running check program: unexpected status code: %d", statusCode)
		}

		consumeBpfDebugLog(t)
	}
}
