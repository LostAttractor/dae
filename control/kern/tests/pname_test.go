//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
)

func TestCurrentOwnerPname(t *testing.T) {
	const child = "DAE_TEST_CURRENT_OWNER"
	want, inChild := os.LookupEnv(child)
	if !inChild {
		if err := features.HaveProgramHelper(ebpf.SchedCLS, asm.FnGetCurrentTask); errors.Is(err, ebpf.ErrNotSupported) {
			t.Skip("kernel does not expose current task to the test classifier")
		} else if err != nil {
			t.Fatal(err)
		}
		for _, test := range []struct{ argv0, want string }{
			{"/bin/actual-name", "actual-name"},
			{"/nix/store/" + strings.Repeat("x", 160) + "/bin/actual-name", ""},
		} {
			cmd := exec.CommandContext(t.Context(), "/proc/self/exe", "-test.run=^TestCurrentOwnerPname$")
			cmd.Args[0] = test.argv0
			cmd.Env = append(os.Environ(), child+"="+test.want)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("argv[0]=%q: %v\n%s", test.argv0, err, output)
			}
		}
		return
	}

	spec, err := loadBpftest()
	if err != nil {
		t.Fatal(err)
	}
	if err := spec.Variables["PARAM"].Set(bpftestDaeParam{HasBpfGetCurrentTask: 1}); err != nil {
		t.Fatal(err)
	}
	var obj struct {
		Program *ebpf.Program `ebpf:"test_current_owner"`
	}
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		t.Fatal(err)
	}
	defer obj.Program.Close()
	if want == "" {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		comm, err := os.ReadFile("/proc/thread-self/comm")
		if err != nil {
			t.Fatal(err)
		}
		want = strings.TrimSuffix(string(comm), "\n")
	}
	status, packet, _, err := runBpfProgram(obj.Program, make([]byte, 64), nil)
	if err != nil || status != 0 {
		t.Fatalf("read current owner: status=%d, %v", status, err)
	}
	if got := strings.TrimRight(string(packet[:16]), "\x00"); got != want {
		t.Fatalf("pname=%q, want %q", got, want)
	}
}
