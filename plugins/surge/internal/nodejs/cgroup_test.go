//go:build linux && surge_nodejs

// SPDX-License-Identifier: AGPL-3.0-only

package nodejs

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/plugins/surge/internal/processgroup"
)

func TestCgroupExternalMemoryAndRecovery(t *testing.T) {
	p, err := NewPool(t.Context(), "", 16<<20, 2, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePool(t, p) })
	healthy := acquire(t, p)
	if err := healthy.Eval(`globalThis.retained=new Uint8Array(52*1024*1024); retained.fill(1);`); err != nil {
		t.Fatal(err)
	}
	vm := acquire(t, p)
	w := vm.worker
	for name, want := range map[string]string{"memory.max": strconv.FormatInt(p.workerMemory, 10), "memory.swap.max": "0", "memory.oom.group": "1"} {
		data, err := os.ReadFile(filepath.Join(w.Group.Path, name))
		if err != nil || strings.TrimSpace(string(data)) != want {
			t.Fatalf("%s=%q err=%v", name, data, err)
		}
	}
	members, err := w.Group.Procs(false)
	if err != nil || !slices.Contains(members, uint64(w.Cmd.Process.Pid)) {
		t.Fatalf("worker membership: %v %v", members, err)
	}
	if target, _ := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", w.Cmd.SysProcAttr.CgroupFD)); target == w.Group.Path {
		t.Fatal("cgroup descriptor retained after process creation")
	}
	ctx := vm.ctx
	err = vm.Eval(`const retained=[]; for(let i=0;i<32;i++){const a=new Uint8Array(8*1024*1024);a.fill(1);retained.push(a);}`)
	if !errors.Is(err, processgroup.ErrOOMKilled) || ctx.Err() != nil {
		t.Fatalf("expected kernel termination before timeout: %v / %v", err, ctx.Err())
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("OOM classification lost the underlying I/O error: %v", err)
	}
	vm.Close()
	s := p.Stats()
	if s.CgroupOOMKills == 0 || s.Discarded != 1 || s.CgroupSampledAt.IsZero() {
		t.Fatalf("missing kernel OOM accounting: %+v", s)
	}
	t.Logf("worker limit=%.2f MiB pool peak=%.2f MiB oom_kill=%d", float64(p.workerMemory)/(1<<20), float64(s.CgroupMemoryPeakBytes)/(1<<20), s.CgroupOOMKills)
	if _, err := os.Stat(w.Group.Path); !os.IsNotExist(err) {
		t.Fatal("OOM worker cgroup retained", err)
	}
	next := acquire(t, p)
	if next.worker == w {
		t.Fatal("OOM worker reused")
	}
	if err := next.Eval("42"); err != nil {
		t.Fatal(err)
	}
	next.Close()
	if err := healthy.Eval(`if(retained[0]!==1)throw Error("lost state")`); err != nil {
		t.Fatal("healthy worker did not survive OOM replacement", err)
	}
	path := p.group.Path
	closePool(t, p)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("pool cgroup retained", err)
	}
	if got := p.Stats(); got.CgroupMemoryBytes != 0 || got.CgroupOOMKills != s.CgroupOOMKills {
		t.Fatalf("shutdown statistics: %+v", got)
	}
}
