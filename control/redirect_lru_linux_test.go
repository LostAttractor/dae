// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>

package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

type redirectLRUKey struct {
	Source      [16]byte
	Destination [16]byte
}

type redirectLRUValue struct {
	Ifindex uint32
	Source  [6]byte
	Dest    [6]byte
	FromWAN uint8
	_       [3]byte
}

type redirectLRUOperation struct {
	Update    uint32
	UpdateKey redirectLRUKey
	LookupKey redirectLRUKey
}

func newRedirectLRUMap(tb testing.TB, flags uint32) *ebpf.Map {
	tb.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "redirect_lru",
		Type:       ebpf.LRUHash,
		KeySize:    uint32(unsafe.Sizeof(redirectLRUKey{})),
		ValueSize:  uint32(unsafe.Sizeof(redirectLRUValue{})),
		MaxEntries: 65536,
		Flags:      flags,
	})
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			tb.Skip("creating an eBPF map requires privileges")
		}
		tb.Fatal(err)
	}
	tb.Cleanup(func() { m.Close() })
	return m
}

func allowedCPUs() ([]int, unix.CPUSet, error) {
	var set unix.CPUSet
	if err := unix.SchedGetaffinity(0, &set); err != nil {
		return nil, set, err
	}
	cpus := make([]int, 0, 128)
	for cpu := 0; cpu < 1024; cpu++ {
		if set.IsSet(cpu) {
			cpus = append(cpus, cpu)
		}
	}
	return cpus, set, nil
}

func pinCurrentThread(cpu int) (unix.CPUSet, error) {
	var original unix.CPUSet
	if err := unix.SchedGetaffinity(0, &original); err != nil {
		return original, err
	}
	var set unix.CPUSet
	set.Set(cpu)
	return original, unix.SchedSetaffinity(0, &set)
}

func runOnCPU(cpu int, fn func() error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		original, pinErr := pinCurrentThread(cpu)
		var fnErr, restoreErr error
		if pinErr == nil {
			fnErr = fn()
			restoreErr = unix.SchedSetaffinity(0, &original)
		}
		runtime.UnlockOSThread()
		done <- errors.Join(pinErr, fnErr, restoreErr)
	}()
	return <-done
}

func newRedirectLRUProgram(tb testing.TB, m *ebpf.Map) *ebpf.Program {
	tb.Helper()
	const (
		operationOffset = -72
		operationSize   = int32(unsafe.Sizeof(redirectLRUOperation{}))
		updateKeyOffset = -68
		lookupKeyOffset = -36
		valueOffset     = -96
	)
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, 0),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, operationOffset),
		asm.Mov.Imm(asm.R4, operationSize),
		asm.FnSkbLoadBytes.Call(),
		asm.JNE.Imm(asm.R0, 0, "input_error"),
		asm.LoadMem(asm.R7, asm.RFP, operationOffset, asm.Word),
		asm.JEq.Imm(asm.R7, 0, "lookup"),
		asm.Mov.Imm(asm.R8, 0),
		asm.StoreMem(asm.RFP, valueOffset, asm.R8, asm.DWord),
		asm.StoreMem(asm.RFP, valueOffset+8, asm.R8, asm.DWord),
		asm.StoreMem(asm.RFP, valueOffset+16, asm.R8, asm.Word),
		asm.LoadMapPtr(asm.R1, m.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, updateKeyOffset),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, valueOffset),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.JNE.Imm(asm.R0, 0, "update_error"),
		asm.LoadMapPtr(asm.R1, m.FD()).WithSymbol("lookup"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, lookupKeyOffset),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "miss"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("miss"),
		asm.Return(),
		asm.Mov.Imm(asm.R0, 2).WithSymbol("update_error"),
		asm.Return(),
		asm.Mov.Imm(asm.R0, 3).WithSymbol("input_error"),
		asm.Return(),
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "redirect_lru_op",
		Type:         ebpf.SocketFilter,
		License:      "GPL",
		Instructions: insns,
	})
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			tb.Skip("loading an eBPF program requires privileges")
		}
		tb.Fatal(err)
	}
	tb.Cleanup(func() { prog.Close() })
	return prog
}

func runRedirectLRUProgram(prog *ebpf.Program, operation *redirectLRUOperation) (uint32, error) {
	const ethernetHeaderLen = 14
	var data [ethernetHeaderLen + unsafe.Sizeof(redirectLRUOperation{})]byte

	// Use an experimental EtherType so test-run leaves the key payload intact.
	data[12], data[13] = 0x88, 0xb5
	operationBytes := unsafe.Slice(
		(*byte)(unsafe.Pointer(operation)), int(unsafe.Sizeof(*operation)))
	copy(data[ethernetHeaderLen:], operationBytes)
	return prog.Run(&ebpf.RunOptions{
		Data:   data[:],
		Repeat: 1,
	})
}

type redirectLRUResult struct {
	status uint32
	err    error
}

type redirectLRUCPURunner struct {
	jobs       chan redirectLRUOperation
	results    chan redirectLRUResult
	restoreErr chan error
	done       chan struct{}
}

func newRedirectLRUCPURunner(tb testing.TB, prog *ebpf.Program, cpu int) *redirectLRUCPURunner {
	tb.Helper()
	runner := &redirectLRUCPURunner{
		jobs:       make(chan redirectLRUOperation),
		results:    make(chan redirectLRUResult),
		restoreErr: make(chan error, 1),
		done:       make(chan struct{}),
	}
	ready := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		original, err := pinCurrentThread(cpu)
		if err != nil {
			ready <- err
			runtime.UnlockOSThread()
			runner.restoreErr <- nil
			close(runner.done)
			return
		}
		ready <- nil
		for operation := range runner.jobs {
			status, err := runRedirectLRUProgram(prog, &operation)
			runner.results <- redirectLRUResult{status, err}
		}
		runner.restoreErr <- unix.SchedSetaffinity(0, &original)
		runtime.UnlockOSThread()
		close(runner.done)
	}()
	if err := <-ready; err != nil {
		<-runner.done
		tb.Fatalf("pin CPU %d runner: %v", cpu, err)
	}
	tb.Cleanup(func() {
		close(runner.jobs)
		<-runner.done
		if err := <-runner.restoreErr; err != nil {
			tb.Errorf("restore CPU %d runner affinity: %v", cpu, err)
		}
	})
	return runner
}

func (r *redirectLRUCPURunner) run(operation redirectLRUOperation) (uint32, error) {
	r.jobs <- operation
	result := <-r.results
	return result.status, result.err
}

func redirectLRUTestKey(worker, sequence uint64) redirectLRUKey {
	var key redirectLRUKey
	binary.NativeEndian.PutUint64(key.Source[:8], worker)
	binary.NativeEndian.PutUint64(key.Destination[:8], sequence)
	return key
}

func TestRedirectTrackDistributedLRUCrossCPU(t *testing.T) {
	cpus, _, err := allowedCPUs()
	if err != nil {
		t.Fatal(err)
	}
	if len(cpus) < 2 {
		t.Skip("cross-CPU test requires at least two allowed CPUs")
	}
	m := newRedirectLRUMap(t, unix.BPF_F_NO_COMMON_LRU)
	prog := newRedirectLRUProgram(t, m)
	key := redirectLRUTestKey(1, 2)
	if err := runOnCPU(cpus[0], func() error {
		status, err := runRedirectLRUProgram(prog, &redirectLRUOperation{
			Update: 1, UpdateKey: key, LookupKey: key,
		})
		if err != nil {
			return err
		}
		if status != 0 {
			return fmt.Errorf("status %d, want 0", status)
		}
		return nil
	}); err != nil {
		t.Fatalf("CPU %d update and lookup: %v", cpus[0], err)
	}
	if err := runOnCPU(cpus[1], func() error {
		status, err := runRedirectLRUProgram(prog, &redirectLRUOperation{LookupKey: key})
		if err != nil {
			return err
		}
		if status != 0 {
			return fmt.Errorf("status %d, want 0", status)
		}
		return nil
	}); err != nil {
		t.Fatalf("CPU %d lookup: %v", cpus[1], err)
	}
	var got redirectLRUValue
	if err := m.Lookup(&key, &got); err != nil {
		t.Fatalf("lookup inserted key from userspace: %v", err)
	}
	if got != (redirectLRUValue{}) {
		t.Fatalf("inserted value = %+v, want zero value", got)
	}
}

func benchmarkRedirectLRU(b *testing.B, flags uint32, workers int, churn bool) {
	b.Helper()
	m := newRedirectLRUMap(b, flags)
	prog := newRedirectLRUProgram(b, m)
	cpus, _, err := allowedCPUs()
	if err != nil {
		b.Fatal(err)
	}
	if workers > len(cpus) {
		b.Skipf("need %d allowed CPUs, have %d", workers, len(cpus))
	}
	if err := runOnCPU(cpus[0], func() error {
		status, err := runRedirectLRUProgram(prog, &redirectLRUOperation{})
		if err != nil {
			return err
		}
		if status != 1 {
			return fmt.Errorf("status %d, want 1", status)
		}
		return nil
	}); err != nil {
		b.Fatalf("probe BPF operation: %v", err)
	}

	for worker := 0; worker < workers; worker++ {
		key := redirectLRUTestKey(uint64(worker+1), 0)
		if err := runOnCPU(cpus[worker], func() error {
			status, err := runRedirectLRUProgram(prog, &redirectLRUOperation{
				Update: 1, UpdateKey: key, LookupKey: key,
			})
			if err != nil {
				return err
			}
			if status != 0 {
				return fmt.Errorf("status %d, want 0", status)
			}
			return nil
		}); err != nil {
			b.Fatalf("initialize worker %d: %v", worker, err)
		}
	}

	iterations := make([]int, workers)
	for i := 0; i < b.N; i++ {
		iterations[i%workers]++
	}
	start := make(chan struct{})
	var ready, done sync.WaitGroup
	var misses atomic.Uint64
	ready.Add(workers)
	done.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func(worker, count, cpu int) {
			defer done.Done()
			runtime.LockOSThread()
			original, err := pinCurrentThread(cpu)
			if err != nil {
				b.Errorf("pin worker %d: %v", worker, err)
				ready.Done()
				runtime.UnlockOSThread()
				return
			}
			defer func() {
				if err := unix.SchedSetaffinity(0, &original); err != nil {
					b.Errorf("restore worker %d affinity: %v", worker, err)
				}
				runtime.UnlockOSThread()
			}()
			ready.Done()
			<-start
			for i := 0; i < count; i++ {
				sequence := uint64(0)
				if churn {
					sequence = uint64(i + 1)
				}
				key := redirectLRUTestKey(uint64(worker+1), sequence)
				replyKey := key
				if !churn {
					replyKey = redirectLRUTestKey(uint64((worker+workers-1)%workers+1), 0)
				}
				status, err := runRedirectLRUProgram(prog, &redirectLRUOperation{
					Update: 1, UpdateKey: key, LookupKey: replyKey,
				})
				if err != nil || status > 1 {
					b.Errorf("worker %d BPF operation: status %d, error %v", worker, status, err)
					return
				}
				if status == 1 {
					misses.Add(1)
				}
			}
		}(worker, iterations[worker], cpus[worker])
	}
	ready.Wait()
	b.ResetTimer()
	close(start)
	done.Wait()
	b.StopTimer()
	b.ReportMetric(float64(misses.Load())/float64(max(b.N, 1)), "reply-miss/op")
	if churn {
		const retentionWindow = 32768
		retentionMap := newRedirectLRUMap(b, flags)
		retentionProg := newRedirectLRUProgram(b, retentionMap)
		runners := make([]*redirectLRUCPURunner, workers)
		for worker := range workers {
			runners[worker] = newRedirectLRUCPURunner(
				b, retentionProg, cpus[worker])
		}
		sampleCount := min(b.N, retentionWindow)
		type retentionSample struct {
			key    redirectLRUKey
			worker int
		}
		samples := make([]retentionSample, 0, sampleCount)
		for ordinal := 0; ordinal < b.N; ordinal++ {
			worker := ordinal % workers
			key := redirectLRUTestKey(uint64(worker+1), uint64(ordinal+1))
			status, err := runners[worker].run(redirectLRUOperation{
				Update: 1, UpdateKey: key,
			})
			if err != nil || status != 1 {
				b.Fatalf("retention insert %d: status %d, error %v", ordinal, status, err)
			}
			if ordinal >= b.N-sampleCount {
				samples = append(samples, retentionSample{key, worker})
			}
		}
		retentionMisses := 0
		for i := range samples {
			status, err := runners[samples[i].worker].run(redirectLRUOperation{
				LookupKey: samples[i].key,
			})
			if err != nil || status > 1 {
				b.Fatalf("retention lookup %d: status %d, error %v", i, status, err)
			}
			if status == 1 {
				retentionMisses++
			}
		}
		b.ReportMetric(float64(retentionMisses)/float64(max(len(samples), 1)), "retention-miss/op")
	}
}

func BenchmarkRedirectTrackLRU(b *testing.B) {
	cpus, _, err := allowedCPUs()
	if err != nil {
		b.Fatal(err)
	}
	powerOfTwo := 1
	for powerOfTwo*2 <= len(cpus) {
		powerOfTwo *= 2
	}
	workerCounts := []int{powerOfTwo}
	if powerOfTwo > 2 {
		workerCounts = append(workerCounts, powerOfTwo-1)
	}
	workerCounts = append(workerCounts, 1)
	for _, workers := range workerCounts {
		for _, mode := range []struct {
			name  string
			churn bool
		}{
			{name: "hot"},
			{name: "churn", churn: true},
		} {
			b.Run(fmt.Sprintf("shared/%s/cpus=%d", mode.name, workers), func(b *testing.B) {
				benchmarkRedirectLRU(b, 0, workers, mode.churn)
			})
			b.Run(fmt.Sprintf("distributed/%s/cpus=%d", mode.name, workers), func(b *testing.B) {
				benchmarkRedirectLRU(b, unix.BPF_F_NO_COMMON_LRU, workers, mode.churn)
			})
		}
	}
}
