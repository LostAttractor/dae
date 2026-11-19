// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/api/client"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/internal/apiserver"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
)

type replacementFailureState struct{ err error }

func (s *replacementFailureState) Close() error { return s.err }

// Run each test alone with private PID, mount and network namespaces, /run and bpffs.
func TestReplacementFailureAfterBlockKernel(t *testing.T) {
	testReplacementKernel(t, "cancel")
}

func TestReplacementCloseFailureAfterBlockKernel(t *testing.T) {
	testReplacementKernel(t, "close")
}

func TestReplacementReadinessSuccessKernel(t *testing.T) {
	testReplacementKernel(t, "readiness-success")
}

func TestReplacementReadinessFailureKernel(t *testing.T) {
	testReplacementKernel(t, "readiness")
}

func TestReplacementReadinessCanceledKernel(t *testing.T) {
	testReplacementKernel(t, "readiness-canceled")
}

func TestReplacementThawsRenamedLANKernel(t *testing.T) {
	testReplacementKernel(t, "rename")
}

func testReplacementKernel(t *testing.T, mode string) {
	t.Helper()
	if os.Geteuid() != 0 || os.Getenv("DAE_TEST_ISOLATED") != "1" {
		t.Skip("requires root in isolated PID, mount and network namespaces")
	}
	t.Setenv("NOTIFY_SOCKET", "")
	startup, err := OpenStartup()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(startup.Close)
	conn := &nftables.Conn{}
	ct := conn.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: "dae_daemon_test"})
	chain := conn.AddChain(&nftables.Chain{
		Name: "output", Table: ct, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter,
	})
	conn.AddRule(&nftables.Rule{Table: ct, Chain: chain, Exprs: []expr.Any{&expr.Ct{Key: expr.CtKeySTATE, Register: 1}}})
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	lan := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "lan0"}}
	if err := netlink.LinkAdd(lan); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lan); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	wrongLock, err := acquireDaemonLock(filepath.Join(dir, "wrong.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer wrongLock.Close()
	if err := validateDaemonLock(wrongLock); err == nil || !strings.Contains(err.Error(), "different identity") {
		t.Fatalf("unrelated inherited instance lock was accepted: %v", err)
	}
	t.Setenv("DAE_LOCATION_CACHE", dir)
	path := filepath.Join(dir, "config.dae")
	t.Setenv("DAE_REPLACEMENT_TEST_CONFIG", path)
	text := "global { disable_waiting_network:true auto_config_kernel_parameter:true lan_interface:lan0 }\nplugins { fixture {} }\nclient { fixture { ipset:dae_replace_fixture nftset:inet/dae_replace/fixture } }\nrouting { fallback:direct }\n"
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	conf, _, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := InstallDefaultResolver(conf.Global.SoMarkFromDae, conf.Global.DNSResolver)
	if err != nil {
		t.Fatal(err)
	}
	store, err := settings.Open(filepath.Join(dir, "runtime-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	mac := [6]byte{2, 0, 0, 0, 0, 0x42}
	if err := store.Update(func(next *settings.Snapshot) error {
		next.Clients["fixture"] = []string{"02:00:00:00:00:42"}
		next.Clients["candidate"] = []string{"02:00:00:00:00:43"}
		return nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(mode, "readiness") {
		// Exercise real private-generation publication and guard ownership on cold recovery.
		if err := os.MkdirAll("/sys/fs/bpf/dae/replacement_pending", 0700); err != nil {
			t.Fatal(err)
		}
	}
	datapath := control.NewRuntime()
	worker, closeWorker := datapath.NewWorkerClient()
	defer closeWorker()
	defer cleanupKernelResources()
	defer datapath.Close()
	local, err := apiserver.Listen("unix", StatusSocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	blocked := false
	closeErr := errors.New("fixture shared state close failed: https://example.test/private-token")
	state := &replacementFailureState{}
	failClose := mode == "close"
	if failClose {
		state.err = closeErr
	}
	definitions := map[string]plugin.Definition{"fixture": {
		Resources: func(context.Context, plugin.Spec, plugin.Services) (plugin.Resources, error) {
			return plugin.Resources{Plan: new(plugin.Plan)}, nil
		},
		Configure: func(plugin.Spec) (plugin.Factory, error) {
			return func(ctx context.Context, services plugin.Services) (plugin.Plugin, error) {
				shared, release, err := services.SharedStates.Acquire(ctx, "fixture", func() (io.Closer, error) { return state, nil })
				return &sharedStatePlugin{shared, release}, err
			}, nil
		},
	}}
	app := &application{
		options: Options{ConfigFile: path, Startup: startup, LaunchArgs: []string{"-test.run=^TestReplacementPreflightProcess$", "-test.v"}},
		conf:    conf, datapath: datapath, settings: store, resolver: resolver, workerClient: worker,
		localAPI: local, operations: newOperations(), definitions: definitions,
		beginShutdown: func() {
			blocked = true
			if mode == "cancel" {
				cancel()
			}
		},
	}
	plugins, err := configurePlugins(conf, definitions)
	if err != nil {
		t.Fatal(err)
	}
	app.inputs, err = loadControlInputs(ctx, conf, false, nil, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := app.preparePlane(ctx, conf, app.inputs, func(download *http.Client) (control.PreparedMITM, error) {
		return loadMITM(ctx, conf, app.certificates.Authority(), download, worker, plugins, nil, nil, datapath)
	})
	if err != nil {
		t.Fatal(err)
	}
	serveKernelTestIngress(t, datapath, conf.Global.TproxyPort)
	if err := app.publishPlane(candidate, false); err != nil {
		t.Fatal(err)
	}
	app.publishAPI()
	if mode == "rename" {
		interfaces, err := datapath.Interfaces()
		if err != nil {
			t.Fatal(err)
		}
		scope := interfaces.NewScope()
		defer scope.Close()
		removed := make(chan struct{}, 1)
		if err := scope.RegisterSync("lan0", nil, nil, func(netlink.Link) { removed <- struct{}{} }); err != nil {
			t.Fatal(err)
		}
		snapshot, err := datapath.ExportReplacement(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer snapshot.Release()
		if err := netlink.LinkSetDown(lan); err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetName(lan, "unmanaged"); err != nil {
			t.Fatal(err)
		}
		select {
		case <-removed:
		case <-time.After(5 * time.Second):
			t.Fatal("rename was not delivered")
		}
		count := func() int {
			t.Helper()
			result, err := link.QueryPrograms(link.QueryOptions{Target: lan.Index, Attach: ebpf.AttachTCXIngress})
			if err != nil {
				t.Fatal(err)
			}
			return len(result.Programs)
		}
		if err := snapshot.Block(ctx); err == nil || count() != 1 {
			t.Fatalf("rename did not reject Block while preserving the frozen link: %v", err)
		}
		snapshot.Release()
		for deadline := time.Now().Add(5 * time.Second); count() != 0; {
			if time.Now().After(deadline) {
				t.Fatal("out-of-scope LAN hook survived thaw")
			}
			time.Sleep(10 * time.Millisecond)
		}
		return
	}
	remote, err := client.New(client.Options{Endpoint: "unix://" + StatusSocketPath})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: "dae_replace"}
	requirePredecessorExports := func() {
		t.Helper()
		sets, err := netlink.IpsetListAll()
		if err != nil {
			t.Fatal(err)
		}
		if len(sets) != 1 || sets[0].SetName != "dae_replace_fixture" {
			t.Fatalf("preflight created an export or backup before commit: %+v", sets)
		}
		if len(sets[0].Entries) != 1 || !slices.Equal(sets[0].Entries[0].MAC, mac[:]) {
			t.Fatalf("preflight changed predecessor ipset before commit: %+v", sets[0].Entries)
		}
		set, err := conn.GetSetByName(table, "fixture")
		if err != nil {
			t.Fatal(err)
		}
		members, err := conn.GetSetElements(set)
		if err != nil || len(members) != 1 || !slices.Equal(members[0].Key, mac[:]) {
			t.Fatalf("preflight changed predecessor nftset before commit: %v, %v", members, err)
		}
		setsNFT, err := conn.GetSets(table)
		if err != nil || len(setsNFT) != 1 || setsNFT[0].Name != "fixture" {
			t.Fatalf("preflight created an nft export before commit: %v, %v", setsNFT, err)
		}
	}
	requirePredecessorExports()
	fixedIndex := control.GetDaeNetns().Dae0().Attrs().Index
	fixedNamespace, err := os.Stat("/run/netns/daens")
	if err != nil {
		t.Fatal(err)
	}
	fixedSocket, err := os.Stat(StatusSocketPath)
	if err != nil {
		t.Fatal(err)
	}
	requireGuardsAndFixedObjects := func() {
		t.Helper()
		guards, err := filepath.Glob("/sys/fs/bpf/dae/guards/*/link")
		if err != nil || len(guards) == 0 {
			t.Fatalf("failed startup did not retain ingress guards: %v %v", guards, err)
		}
		link, err := netlink.LinkByName("dae0")
		if err != nil || link.Attrs().Index != fixedIndex {
			t.Fatalf("failed startup deleted or changed the fixed veth: %v", err)
		}
		current, err := os.Stat("/run/netns/daens")
		if err != nil || !os.SameFile(current, fixedNamespace) {
			t.Fatalf("failed startup deleted or changed the fixed namespace: %v", err)
		}
		current, err = os.Stat(StatusSocketPath)
		if err != nil || !os.SameFile(current, fixedSocket) {
			t.Fatalf("failed startup deleted or changed the fixed API socket: %v", err)
		}
	}
	if strings.HasPrefix(mode, "readiness") {
		app.staging = true
		control.GetDaeNetns().SetOwnership(false)
		local.SetOwnership(false)
		guards, err := filepath.Glob("/sys/fs/bpf/dae/guards/*/link")
		if err != nil || len(guards) == 0 {
			t.Fatalf("private generation lost its guards before READY: %v %v", guards, err)
		}
		notifyPath := filepath.Join(dir, "notify.sock")
		t.Setenv("NOTIFY_SOCKET", notifyPath)
		var notify *net.UnixConn
		if mode == "readiness-success" {
			notify, err = net.ListenUnixgram("unixgram", &net.UnixAddr{Name: notifyPath, Net: "unixgram"})
			if err != nil {
				t.Fatal(err)
			}
			defer notify.Close()
			if err := notify.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
		}
		readyCtx, cancelReady := context.WithCancelCause(ctx)
		defer cancelReady(nil)
		cause := errors.New("fixture replacement startup canceled")
		if mode == "readiness-canceled" {
			cancelReady(cause)
		}
		err = app.finishStartup(readyCtx)
		if mode == "readiness-success" {
			if err != nil || blocked || app.staging {
				t.Fatalf("ready startup did not adopt its resources: blocked=%v staged=%v error=%v", blocked, app.staging, err)
			}
			message := make([]byte, 128)
			n, _, err := notify.ReadFromUnix(message)
			if err != nil || string(message[:n]) != "READY=1" {
				t.Fatalf("readiness notification: %q, %v", message[:n], err)
			}
			if err := exit(datapath, app.localAPI, app.managementAPI); err != nil {
				t.Fatal(err)
			}
			if err := cleanupKernelResources(); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{StatusSocketPath, "/run/netns/daens"} {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("successful startup retained owned path %s: %v", path, err)
				}
			}
			if _, err := netlink.LinkByIndex(fixedIndex); err == nil {
				t.Fatal("successful startup retained its owned network link")
			} else if _, missing := errors.AsType[netlink.LinkNotFoundError](err); !missing {
				t.Fatal(err)
			}
			return
		}
		if err == nil || !blocked || !app.staging {
			t.Fatalf("late readiness failure did not re-block the committed runtime: blocked=%v staged=%v error=%v", blocked, app.staging, err)
		}
		if mode == "readiness-canceled" && !errors.Is(err, cause) || mode == "readiness" && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("late readiness failure lost its original cause: %v", err)
		}
		if err := exit(datapath, app.localAPI, app.managementAPI); err != nil {
			t.Fatal(err)
		}
		if err := cleanupKernelResources(); err != nil {
			t.Fatal(err)
		}
		requirePredecessorExports()
		requireGuardsAndFixedObjects()
		return
	}
	text = strings.Replace(text, "client {", "client { candidate { ipset:dae_replace_candidate nftset:inet/dae_replace/candidate }", 1)
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	newOperation := func() api.Operation {
		t.Helper()
		op, err := app.operations.submit(api.OperationRequest{Kind: "reload"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		<-app.operations.requests
		app.operations.start(op.ID)
		return op
	}

	// The target's actual plugin preflight provides a deterministic API observation window.
	controlPath := filepath.Join(dir, "preflight.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: controlPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("DAE_REPLACEMENT_TEST_CONTROL", controlPath)
	for _, canceled := range []bool{false, true} {
		probeCtx, cancelProbe := context.WithCancel(ctx)
		defer cancelProbe()
		op := newOperation()
		finished := make(chan error, 1)
		go func() { _, err := app.replace(probeCtx, op.ID, executable, nil); finished <- err }()
		if err := listener.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		probe, err := listener.AcceptUnix()
		if err != nil {
			t.Fatal(err)
		}
		defer probe.Close()
		if err := probe.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		var ready [1]byte
		if _, err := io.ReadFull(probe, ready[:]); err != nil || ready[0] != 1 {
			t.Fatalf("target did not enter real preflight: %v %v", ready, err)
		}
		if _, err := remote.Status(ctx); err != nil {
			t.Fatalf("preflight paused the serving API: %v", err)
		}
		_, err = remote.SubmitOperation(ctx, api.OperationRequest{Kind: "reload"})
		if response, ok := errors.AsType[*client.Error](err); !ok || response.StatusCode != http.StatusConflict {
			t.Fatalf("preflight accepted another configuration operation: %v", err)
		}
		requirePredecessorExports()
		if canceled {
			cancelProbe()
		} else if _, err := probe.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		select {
		case err = <-finished:
		case <-time.After(10 * time.Second):
			t.Fatal("target preflight did not finish")
		}
		if err == nil || !canceled && !strings.Contains(err.Error(), "fixture preflight rejected") || blocked {
			t.Fatalf("preflight failure retired the old runtime: canceled=%v blocked=%v error=%v", canceled, blocked, err)
		}
		if _, fatal := errors.AsType[*activationError](err); fatal {
			t.Fatalf("pre-Block failure became fatal: %v", err)
		}
		app.operations.finish(op.ID, "", err)
		if duplicate, err := AcquireLock(); err == nil {
			duplicate.Close()
			t.Fatal("preflight exit released its parent's borrowed instance lock")
		}
		if _, err := remote.Status(ctx); err != nil {
			t.Fatalf("preflight failure did not preserve the serving API: %v", err)
		}
		requirePredecessorExports()
		cancelProbe()
	}
	t.Setenv("DAE_REPLACEMENT_TEST_CONTROL", "")
	oversized := newOperation()
	app.operations.mu.Lock()
	app.operations.records[oversized.ID].status.Trigger = strings.Repeat("x", 64<<10)
	app.operations.mu.Unlock()
	_, err = app.replace(ctx, oversized.ID, executable, nil)
	if err == nil || !strings.Contains(err.Error(), "handoff state exceeds 64 KiB") || blocked {
		t.Fatalf("manifest failure retired the old runtime: blocked=%v error=%v", blocked, err)
	}
	if _, fatal := errors.AsType[*activationError](err); fatal {
		t.Fatalf("manifest preparation failure became fatal: %v", err)
	}
	app.operations.finish(oversized.ID, "", err)
	if _, err := remote.Status(ctx); err != nil {
		t.Fatalf("manifest preparation failure did not preserve the serving API: %v", err)
	}
	if guards, err := filepath.Glob("/sys/fs/bpf/dae/guards/*/link"); err != nil || len(guards) != 0 {
		t.Fatalf("manifest preparation failure installed guards: %v %v", guards, err)
	}
	requirePredecessorExports()
	if err := os.WriteFile(filepath.Join(dir, "runtime-state.json"), []byte("invalid settings"), 0600); err != nil {
		t.Fatal(err)
	}

	readyToBlock := false
	app.progress = func(message string) {
		if message == "Blocking captured traffic and closing old connections..." {
			readyToBlock = true
			requirePredecessorExports()
			_, err := remote.Status(ctx)
			if response, ok := errors.AsType[*client.Error](err); !ok || response.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("API was not drained immediately before Block: %v", err)
			}
		}
	}
	op := newOperation()
	logReader, logWriter := replacementLogPipe(t)
	_, err = app.replace(ctx, op.ID, executable, logWriter)
	if _, fatal := errors.AsType[*activationError](err); !blocked || !fatal {
		t.Fatalf("blocked=%v, replacement error=%v", blocked, err)
	}
	if failClose && !errors.Is(err, closeErr) || !failClose && !errors.Is(err, context.Canceled) {
		t.Fatalf("replacement lost the post-Block failure: %v", err)
	}
	_ = logWriter.Close()
	if err := logReader.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(logReader)
	want := "context canceled"
	if failClose {
		want = "fixture shared state close failed: https://example.test"
	}
	if err != nil || !strings.Contains(string(output), "Replacement failed after blocking captured traffic: ") || !strings.Contains(string(output), want) || strings.Contains(string(output), "private-token") {
		t.Fatalf("post-Block diagnostic = %q, %v", output, err)
	}
	if !readyToBlock {
		t.Fatal("replacement did not reach the pre-Block API barrier")
	}
	if err := cleanupKernelResources(); err != nil {
		t.Fatal(err)
	}
	requirePredecessorExports()
	requireGuardsAndFixedObjects()
}
