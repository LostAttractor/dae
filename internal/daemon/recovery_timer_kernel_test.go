// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/config"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
)

// Run alone with private PID, mount and network namespaces, /run and bpffs.
func TestFailedRecoveryTimerPinsKernel(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("DAE_TEST_ISOLATED") != "1" {
		t.Skip("requires root in isolated PID, mount and network namespaces")
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	if os.Getenv("DAE_TIMER_RECOVERY_CHILD") == "1" {
		startup, err := OpenStartup()
		must(err)
		defer startup.Close()
		path := os.Getenv("DAE_TIMER_RECOVERY_CONFIG")
		conf, dirs, err := config.Load(path)
		must(err)
		resolver, err := InstallDefaultResolver(conf.Global.SoMarkFromDae, conf.Global.DNSResolver)
		must(err)
		failure := errors.New("live plugin constructor failure")
		definitions := map[string]plugin.Definition{"fixture": {
			Resources: func(context.Context, plugin.Spec, plugin.Services) (plugin.Resources, error) {
				return plugin.Resources{Plan: new(plugin.Plan)}, nil
			},
			Configure: func(plugin.Spec) (plugin.Factory, error) {
				return func(context.Context, plugin.Services) (plugin.Plugin, error) { return nil, failure }, nil
			},
		}}
		err = Run(conf, dirs, definitions, resolver, Options{Startup: startup, ConfigFile: path})
		if !errors.Is(err, failure) {
			t.Fatalf("Run did not reach live plugin construction after BPF preparation: %v", err)
		}
		return
	}
	t.Setenv("NOTIFY_SOCKET", "")
	loopback, err := netlink.LinkByName("lo")
	must(err)
	must(netlink.LinkSetUp(loopback))
	dir := t.TempDir()
	t.Setenv("DAE_LOCATION_CACHE", dir)
	configPath := filepath.Join(dir, "config.dae")
	must(os.WriteFile(configPath, []byte("global { disable_waiting_network:true auto_config_kernel_parameter:true lan_interface:timer-lan0 }\nplugins { fixture {} }\nrouting { fallback:direct }\n"), 0600))
	conn := &nftables.Conn{}
	table := conn.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: "timer_recovery"})
	chain := conn.AddChain(&nftables.Chain{Name: "output", Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter})
	conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: []expr.Any{&expr.Ct{Key: expr.CtKeySTATE, Register: 1}}})
	must(conn.Flush())
	device := &netlink.Dummy{Name: "timer-lan0"}
	must(netlink.LinkAdd(device))
	defer netlink.LinkDel(device)
	must(netlink.LinkSetUp(device))
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.SchedCLS, License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()}})
	must(err)
	defer program.Close()
	guard, err := link.AttachTCX(link.TCXOptions{Interface: device.Index, Attach: ebpf.AttachTCXIngress, Program: program})
	must(err)
	defer guard.Close()
	guardInfo, err := guard.Info()
	must(err)
	root := filepath.Join(consts.BpfPinRoot, consts.AppName)
	guardDirectory := filepath.Join(root, "guards", fmt.Sprint(guardInfo.ID))
	must(os.MkdirAll(guardDirectory, 0700))
	must(guard.Pin(filepath.Join(guardDirectory, "link")))
	executable, err := os.Executable()
	must(err)
	for attempt := range 2 {
		command := exec.CommandContext(t.Context(), executable, "-test.run=^TestFailedRecoveryTimerPinsKernel$", "-test.v", "-test.timeout=45s")
		command.Env = append(os.Environ(), "DAE_TIMER_RECOVERY_CHILD=1", "DAE_TIMER_RECOVERY_CONFIG="+configPath)
		output, err := command.CombinedOutput()
		t.Logf("recovery attempt %d:\n%s", attempt+1, output)
		must(err)
		entries, err := os.ReadDir(root)
		must(err)
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "runtime_") {
				t.Errorf("failed recovery retained timer pins without any successor entry: %s", entry.Name())
			}
		}
		retained, err := link.LoadPinnedLink(filepath.Join(guardDirectory, "link"), nil)
		must(err)
		current, err := retained.Info()
		must(errors.Join(err, retained.Close()))
		if current.ID != guardInfo.ID || current.Program != guardInfo.Program || current.TCX().Ifindex != uint32(device.Index) {
			t.Fatalf("failed recovery changed the old guard: %+v", current)
		}
		verdict, _, err := program.Test(make([]byte, 64))
		must(err)
		if verdict != 2 {
			t.Fatalf("old guard is not fail-closed: verdict=%d", verdict)
		}
	}
}
