//go:build trace && (amd64 || arm64 || riscv64 || loong64 || ppc64 || ppc64le)

package trace

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// Run the actual entry, cleanup and return BPF programs against a private
// process. Its invalid skb address is only a map key; failed kernel reads are
// intentional. Re-publishing that address while cleanup is in progress models
// reuse on another CPU without allowing the old cleanup to alter the new trace.
func TestNAPIRetirementGuardsCleanupAndAddressReuse(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("loading trace BPF requires root")
	}
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("fixture requires a C compiler")
	}
	dir := t.TempDir()
	source, fixtureBinary := filepath.Join(dir, "fixture.c"), filepath.Join(dir, "fixture")
	const fixture = `
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdint.h>
__attribute__((noinline)) void visit_fixture(void *skb) {
    asm volatile("" : : "r"(skb) : "memory");
}
__attribute__((noinline)) void release_fixture(void *skb, unsigned int reason) {
    putchar('e'); fflush(stdout);
    getchar();
    visit_fixture(skb);
}
int main(void) {
    cpu_set_t cpus;
    CPU_ZERO(&cpus); CPU_SET(sched_getcpu(), &cpus);
    if (sched_setaffinity(0, sizeof(cpus), &cpus)) return 2;
    putchar('r'); fflush(stdout);
    int command;
    while ((command = getchar()) != EOF) {
        if (command == 'f') release_fixture((void *)(uintptr_t)0x123450, 9);
        else visit_fixture((void *)(uintptr_t)0x123450);
        putchar('d'); fflush(stdout);
    }
    return 0;
}`
	if err := os.WriteFile(source, []byte(fixture), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.CommandContext(t.Context(), cc, "-O0", "-g", "-o", fixtureBinary, source).CombinedOutput(); err != nil {
		t.Fatalf("compile fixture: %v\n%s", err, output)
	}
	objs, _, err := rewriteAndLoadBpf(4, syscall.IPPROTO_UDP, 53, dropReasonConfig{notDropped: 0, consumed: 1, napiReason: 1}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer objs.Close()
	events, err := ringbuf.NewReader(objs.events)
	if err != nil {
		t.Fatal(err)
	}
	defer events.Close()
	events.SetDeadline(time.Now().Add(10 * time.Second))
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, fixtureBinary)
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = input.Close(); cancel(); _ = cmd.Wait() }()
	expect := func(want byte) {
		t.Helper()
		var got [1]byte
		if _, err := io.ReadFull(output, got[:]); err != nil || got[0] != want {
			t.Fatalf("fixture reply %q, %v; want %q; stderr=%s", got, err, want, &stderr)
		}
	}
	expect('r')
	executable, err := link.OpenExecutable(fixtureBinary)
	if err != nil {
		t.Fatal(err)
	}
	opts := &link.UprobeOptions{PID: cmd.Process.Pid}
	returnHook, err := executable.Uretprobe("release_fixture", objs.napiExit, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer returnHook.Close()
	entryHook, err := executable.Uprobe("release_fixture", objs.napiEntry, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer entryHook.Close()
	visitHook, err := executable.Uprobe("visit_fixture", objs.skbPrograms[0][0], opts)
	if err != nil {
		t.Fatal(err)
	}
	defer visitHook.Close()
	states := objs.collection.Maps["trace_states"]
	address := uint64(0x123450)
	state := bpfTraceState{Generation: 1}
	if err := states.Put(address, state); err != nil {
		t.Fatal(err)
	}
	_, _ = input.Write([]byte{'f'})
	expect('e')
	if err := states.Lookup(address, &state); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("entry retained the old incarnation: %+v, %v", state, err)
	}
	record, err := events.Read()
	if err != nil {
		t.Fatal(err)
	}
	var event traceEvent
	if err := binary.Read(bytes.NewReader(record.RawSample), nativeEndian, &event); err != nil {
		t.Fatal(err)
	}
	if event.Generation != 1 || event.Flags != eventFlagTerminal|eventFlagDrop|eventFlagDropReason || event.DropReason != 9 {
		t.Fatalf("NAPI terminal lost its generation or reason: %+v", event)
	}
	state = bpfTraceState{Generation: 2}
	if err := states.Put(address, state); err != nil {
		t.Fatal(err)
	}
	_, _ = input.Write([]byte{'c'})
	expect('d')
	if err := states.Lookup(address, &state); err != nil || state.Generation != 2 || state.NextSequence != 0 {
		t.Fatalf("old cleanup changed the new incarnation: %+v, %v", state, err)
	}
	_, _ = input.Write([]byte{'v'})
	expect('d')
	if err := states.Lookup(address, &state); err != nil || state.Generation != 2 || state.NextSequence != 1 {
		t.Fatalf("return guard suppressed later use: %+v, %v", state, err)
	}
	var runtime bpfRuntimeState
	if err := objs.runtime.Lookup(uint32(0), &runtime); err != nil || runtime.RetirementActive != 0 || runtime.RetirementOverflows != 0 {
		t.Fatalf("unbalanced retirement guard: %+v, %v", runtime, err)
	}
}

func TestNAPIKernelReturnAttach(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("attaching trace BPF requires root")
	}
	if err := ReadKallsyms(); err != nil {
		t.Fatal(err)
	}
	if _, exists := kallsymsByName["__napi_kfree_skb"]; !exists {
		t.Skip("kernel has no deferred NAPI free function")
	}
	_, _, reasons, _, err := searchAvailableTargets()
	if err != nil {
		t.Fatal(err)
	}
	objs, _, err := rewriteAndLoadBpf(4, syscall.IPPROTO_UDP, 53, reasons, false)
	if err != nil {
		t.Fatal(err)
	}
	defer objs.Close()
	attached, err := attachNapiReturn(objs)
	if err != nil {
		t.Fatal(err)
	}
	defer attached.Close()
	if info, err := attached.Info(); err == nil {
		t.Logf("NAPI return attachment type: %d", info.Type)
	}
}
