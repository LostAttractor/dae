// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/settings"
	"github.com/vishvananda/netlink"
)

func TestReplacementSnapshotFileOwnership(t *testing.T) {
	for _, ownership := range []string{"retained", "transferred"} {
		t.Run(ownership, func(t *testing.T) {
			file, err := os.CreateTemp(t.TempDir(), "attachment")
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			snapshot := &ReplacementSnapshot{Files: []*os.File{file}}
			if ownership == "transferred" {
				if files := snapshot.TakeFiles(); len(files) != 1 || files[0] != file {
					t.Fatal("TakeFiles did not transfer the original file")
				}
				if snapshot.Files != nil || snapshot.TakeFiles() != nil {
					t.Fatal("snapshot retained ownership of transferred files")
				}
			}
			snapshot.Release()
			snapshot.Release()
			if snapshot.Files != nil {
				t.Fatal("released snapshot retained files")
			}
			_, err = file.Stat()
			if ownership == "transferred" && err != nil {
				t.Fatalf("Release closed a transferred file: %v", err)
			}
			if ownership == "retained" && !errors.Is(err, os.ErrClosed) {
				t.Fatalf("Release did not close its file: %v", err)
			}
		})
	}
}

func TestReplacementOpensFinalSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime-state.json")
	oldStore, err := settings.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	old := newAPITestPlane(t, oldStore)
	handler := old.apiHandler("test", testClientIngress, nil, nil)
	w := apiTestRequest(handler, "PUT", "/api/device/sets/gaming", "", "")
	if w.Code != 200 {
		t.Fatalf("predecessor membership write: %d %s", w.Code, w.Body.String())
	}
	selected := old.outbounds[0].Dialers[1].StatsID()
	w = apiTestRequest(handler, "PUT", "/api/selectors/proxy", `{"node_id":"`+selected+`"}`, "test-secret")
	if w.Code != 200 {
		t.Fatalf("predecessor selector write: %d %s", w.Code, w.Body.String())
	}
	mac := [6]byte{2, 0, 0, 0, 0, 10}
	if err := oldStore.Update(func(next *settings.Snapshot) error {
		next.MITM["02:00:00:00:00:0a"] = false
		return nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	// The manifest releases the successor only after the predecessor's writers drain.
	candidateStore, err := settings.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	requireFinalPreferences := func(store *settings.Store) {
		t.Helper()
		if members := store.Members("gaming"); !slices.Equal(members, [][6]byte{mac}) {
			t.Errorf("lost predecessor membership: %v", members)
		}
		if !oldStore.Selection("proxy").Matches(store.Selection("proxy"), true) {
			t.Error("lost predecessor selector choice")
		}
		if enabled, exists := store.MITM(mac); !exists || enabled {
			t.Errorf("lost explicit MITM preference: enabled=%v exists=%v", enabled, exists)
		}
	}
	requireFinalPreferences(candidateStore)
	candidate := newAPITestPlane(t, candidateStore)
	w = apiTestRequest(candidate.apiHandler("test", testClientIngress, nil, nil), "PUT", "/api/device/sets/streaming", "", "")
	if w.Code != 200 {
		t.Fatalf("successor write: %d %s", w.Code, w.Body.String())
	}
	reopened, err := settings.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	requireFinalPreferences(reopened)
	if members := reopened.Members("streaming"); !slices.Equal(members, [][6]byte{mac}) {
		t.Fatalf("lost successor membership: %v", members)
	}
}

func TestReplacementRejectsInvalidInitialSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime-state.json")
	if err := os.WriteFile(path, []byte("invalid settings"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := settings.Open(path); err == nil {
		t.Fatal("invalid persisted settings passed the successor's first open")
	}
}

func newReplacementRegistryPlane(t *testing.T, dir string) (*ControlPlane, *fakeKernelDomainMaps) {
	t.Helper()
	registry, fake := newTestRegistry(16, time.Hour)
	t.Cleanup(func() { _ = registry.Close() })
	matcher, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", "domain(suffix: example) -> block"))
	runtime := &Runtime{staged: true, kernelLinks: kernelLinks{privatePins: true, preparing: true}}
	plane := &ControlPlane{
		ctx:               t.Context(),
		core:              &controlPlaneCore{closed: t.Context(), domainRegistry: registry, bpf: &BPFState{Runtime: runtime}},
		routingMatcher:    matcher,
		domainRegistryDir: dir,
	}
	runtime.current = plane
	return plane, fake
}

func replacementRegistryFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string]string, len(entries))
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files[entry.Name()] = string(data)
	}
	return files
}

func restoreReplacementRegistryForTest(c *ControlPlane) error {
	c.core.lifecycleMu.Lock()
	defer c.core.lifecycleMu.Unlock()
	return c.restoreDomainRegistry()
}

func activateReplacementForTest(r *Runtime) error {
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	c := r.current
	c.core.lifecycleMu.Lock()
	defer c.core.lifecycleMu.Unlock()
	return r.activateReplacementLocked(c)
}

func TestReplacementRestoresFinalRegistry(t *testing.T) {
	for _, mode := range []string{"append", "compact"} {
		t.Run(mode, func(t *testing.T) {
			dir, now := t.TempDir(), time.Now()
			old, _ := newTestRegistry(16, time.Hour)
			t.Cleanup(func() { _ = old.Close() })
			ip := netip.MustParseAddr("192.0.2.1")
			old.Upsert("initial.example.", ip, testBitmap(), 3600, now)
			persistTestRegistry(t, old, dir, now)
			plane, fake := newReplacementRegistryPlane(t, dir)
			candidate := plane.core.domainRegistry
			projections := 0
			candidate.kernel.update = func(ip netip.Addr, bump, routing []uint32) error {
				if plane.core.lifecycleMu.TryLock() {
					plane.core.lifecycleMu.Unlock()
					t.Fatal("restore did not exclude concurrent shutdown")
				}
				projections++
				return fake.update(ip, bump, routing)
			}
			old.Upsert("late.example.", ip, testBitmap(), 3600, now.Add(time.Minute))
			old.activity.observe(ip, "initial.example.", now.Add(20*time.Minute))
			old.persist.rebuild = mode == "compact"
			if candidate.persist != nil || candidate.Size() != 0 || projections != 0 {
				t.Fatal("candidate restored before the predecessor's final write")
			}
			if err := old.Close(); err != nil {
				t.Fatal(err)
			}
			before := replacementRegistryFiles(t, dir)
			if err := restoreReplacementRegistryForTest(plane); err != nil {
				t.Fatal(err)
			}
			if candidate.persist == nil || candidate.persist.enabled || candidate.persist.rebuild || projections != 1 {
				t.Fatalf("restore state: persistence=%+v, projections=%d", candidate.persist, projections)
			}
			requireDiskEvidence(t, diskEvidence(candidate), diskEvidence(old))
			if !candidate.retention("initial.example.", ip).Equal(now.Add(80 * time.Minute)) {
				t.Fatal("replacement lost the predecessor's final activity renewal")
			}
			wantBitmap := plane.routingMatcher.domainMatcher.MatchDomainBitmap("initial.example.")
			if !slices.Equal(fake.routing[ip], wantBitmap) || slices.Equal(wantBitmap, testBitmap()) {
				t.Fatal("restore did not apply the successor's routing rules")
			}
			if !maps.Equal(replacementRegistryFiles(t, dir), before) {
				t.Fatal("restore rewrote a healthy final store before persistence was enabled")
			}
			// Continue with the ordinary persistence path, not a replacement rebuild.
			candidate.kernel.update = fake.update
			candidate.EnablePersistence(dir)
			candidate.Upsert("successor.example.", ip, wantBitmap, 3600, now)
			candidate.writeRenewals(now)
			if after := replacementRegistryFiles(t, dir); after[domainBaseFile] != before[domainBaseFile] || after[domainJournalFile] == before[domainJournalFile] {
				t.Fatal("successor did not append to the final journal without rebuilding its baseline")
			}
			if err := candidate.Close(); err != nil {
				t.Fatal(err)
			}
			restored := restoreTestRegistry(t, dir, time.Hour, now)
			defer restored.Close()
			requireDiskEvidence(t, diskEvidence(restored), diskEvidence(candidate))
		})
	}
}

func TestReplacementRegistryCloseBeforePersistence(t *testing.T) {
	for _, restore := range []bool{false, true} {
		name := "before-restore"
		if restore {
			name = "after-restore"
		}
		t.Run(name, func(t *testing.T) {
			dir, now := t.TempDir(), time.Now()
			old, _ := newTestRegistry(16, time.Hour)
			t.Cleanup(func() { _ = old.Close() })
			ip := netip.MustParseAddr("192.0.2.1")
			old.Upsert("initial.example.", ip, testBitmap(), 3600, now)
			persistTestRegistry(t, old, dir, now)
			plane, _ := newReplacementRegistryPlane(t, dir)
			candidate := plane.core.domainRegistry
			if restore {
				if err := old.Close(); err != nil {
					t.Fatal(err)
				}
				if err := restoreReplacementRegistryForTest(plane); err != nil {
					t.Fatal(err)
				}
				if candidate.persist == nil || candidate.persist.enabled || !plane.Runtime().staged {
					t.Fatal("failed activation enabled persistence or released staging")
				}
			} else {
				// A complete unpublished baseline and legacy file must remain untouched.
				for name, data := range map[string][]byte{
					domainBaseFile + domainTempSuffix: encodeDomainBase(7, []domainLogEntry{{"temporary.example.", ip, now.Add(time.Hour).UnixNano()}}),
					"domain-registry.json.gz":         []byte("legacy snapshot"),
				} {
					if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			before := replacementRegistryFiles(t, dir)
			candidate.Start()
			candidate.Upsert("discarded.example.", ip, testBitmap(), 3600, now)
			candidate.writeNew(now)
			candidate.writeRenewals(now)
			if err := candidate.Close(); err != nil {
				t.Fatal(err)
			}
			if !maps.Equal(replacementRegistryFiles(t, dir), before) {
				t.Fatal("candidate without persistence changed the predecessor's files")
			}
		})
	}
}

func TestReplacementRegistryProjectionFailureKeepsStaged(t *testing.T) {
	dir, now := t.TempDir(), time.Now()
	old, _ := newTestRegistry(16, time.Hour)
	old.Upsert("initial.example.", netip.MustParseAddr("192.0.2.1"), testBitmap(), 3600, now)
	persistTestRegistry(t, old, dir, now)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	plane, _ := newReplacementRegistryPlane(t, dir)
	candidate := plane.core.domainRegistry
	projectionErr := errors.New("projection failed")
	candidate.kernel.update = func(netip.Addr, []uint32, []uint32) error { return projectionErr }
	err := restoreReplacementRegistryForTest(plane)
	if _, incomplete := errors.AsType[*domainProjectionError](err); !incomplete || !errors.Is(err, projectionErr) {
		t.Fatalf("preparation did not report incomplete projection: %v", err)
	}
	if candidate.persist == nil || candidate.persist.enabled || !plane.Runtime().staged {
		t.Fatal("incomplete projection enabled persistence or released staging")
	}
	before := replacementRegistryFiles(t, dir)
	if err := candidate.Close(); err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(replacementRegistryFiles(t, dir), before) {
		t.Fatal("closing an incomplete candidate wrote back registry state")
	}
}

func TestReplacementRegistryRejectsClosedPlane(t *testing.T) {
	plane, _ := newReplacementRegistryPlane(t, t.TempDir())
	closed, cancel := context.WithCancel(t.Context())
	cancel()
	plane.core.closed = closed
	plane.Runtime().replacementLinks = []replacementAttachment{{}}
	if err := plane.Runtime().CommitReplacement(t.Context()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("commit of closed plane: %v", err)
	}
	if plane.core.domainRegistry.persist != nil || !plane.Runtime().staged {
		t.Fatal("closed plane restored registry state or released staging")
	}
}

func TestReplacementCommitCancellationWithoutHost(t *testing.T) {
	for _, duringRestore := range []bool{false, true} {
		name := "before-commit"
		if duringRestore {
			name = "during-restore"
		}
		t.Run(name, func(t *testing.T) {
			dir, now := t.TempDir(), time.Now()
			old, _ := newTestRegistry(16, time.Hour)
			old.Upsert("deadline.example.", netip.MustParseAddr("192.0.2.1"), testBitmap(), 3600, now)
			persistTestRegistry(t, old, dir, now)
			if err := old.Close(); err != nil {
				t.Fatal(err)
			}
			plane, fake := newReplacementRegistryPlane(t, dir)
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			cause := errors.New("replacement deadline expired")
			restored := false
			plane.core.domainRegistry.kernel.update = func(ip netip.Addr, bump, routing []uint32) error {
				restored = true
				cancel(cause)
				return fake.update(ip, bump, routing)
			}
			if duringRestore {
				if err := restoreReplacementRegistryForTest(plane); err != nil {
					t.Fatal(err)
				}
			} else {
				cancel(cause)
			}
			if plane.MITMHost() != nil || plane.ctx.Err() != nil {
				t.Fatal("test requires a live plane context without a host")
			}
			if err := plane.Runtime().CommitReplacement(ctx); !errors.Is(err, cause) {
				t.Fatalf("commit lost cancellation cause or reached guard retirement: %v", err)
			}
			if restored != duringRestore || !plane.Runtime().staged {
				t.Fatalf("canceled commit changed staging: restored=%v staged=%v", restored, plane.Runtime().staged)
			}
		})
	}
}

func TestReplacementRequiresPreparationBeforeCommit(t *testing.T) {
	r := NewRuntime()
	defer r.Close()
	if err := r.CommitReplacement(t.Context()); err == nil {
		t.Fatal("fresh runtime committed a replacement")
	}
	r.staged, r.kernelLinks.privatePins, r.kernelLinks.preparing = true, true, true
	if err := r.CommitReplacement(t.Context()); err == nil {
		t.Fatal("unpublished replacement committed")
	}
	r.current = &ControlPlane{}
	if err := r.CommitReplacement(t.Context()); err == nil {
		t.Fatal("replacement without pending attachments committed")
	}
}

func TestReplacementValidatesDescriptors(t *testing.T) {
	namespaces := []ReplacementLink{
		{Kind: "netns", Role: 0, ID: 1},
		{Kind: "netns", Role: 1, ID: 2},
		{Kind: "netns", Role: 2, ID: 3},
		{Kind: "netns", Role: 3, ID: 4},
	}
	identities := make([]ReplacementLink, len(socketIdentityAttachTypes))
	for i := range identities {
		identities[i] = ReplacementLink{Kind: "identity", Role: uint8(i), ID: uint32(i + 10)}
	}
	for _, test := range []struct {
		name  string
		links []ReplacementLink
		valid bool
	}{
		{"namespace only", namespaces, true},
		{"identity hooks", append(slices.Clone(namespaces), identities...), true},
		{"WAN without identity", append(slices.Clone(namespaces), ReplacementLink{Kind: "host", Role: uint8(hostTCXWanEgress), Ifindex: 2, ID: 5}), false},
		{"missing DNS reply egress", slices.Delete(slices.Clone(namespaces), netnsPeerEgress, netnsPeerEgress+1), false},
		{"partial identity", append(slices.Clone(namespaces), identities[:4]...), false},
		{"duplicate identity role", append(append(slices.Clone(namespaces), identities...), ReplacementLink{Kind: "identity", Role: 0, ID: 20}), false},
		{"duplicate ID", append(slices.Clone(namespaces), ReplacementLink{Kind: "host", Ifindex: 2, ID: 1}), false},
		{"invalid host role", append(slices.Clone(namespaces), ReplacementLink{Kind: "host", Ifindex: 2, Role: 4, ID: 5}), false},
		{"unknown kind", append(slices.Clone(namespaces), ReplacementLink{Kind: "exit", ID: 5}), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateReplacementDescriptors(test.links); (err == nil) != test.valid {
				t.Fatalf("validation=%v, valid=%v", err, test.valid)
			}
		})
	}
}

func TestReplacementValidatesCompleteInterfaceSet(t *testing.T) {
	wan := &netlink.Dummy{Index: 2, Name: "wan0", EncapType: "ether"}
	added := &netlink.Dummy{Index: 3, Name: "wan1", EncapType: "ether"}
	descriptors := []ReplacementLink{
		{Kind: "host", Ifindex: 2, Role: uint8(hostTCXWanIngress), Ethernet: true},
		{Kind: "host", Ifindex: 2, Role: uint8(hostTCXWanEgress), Ethernet: true},
	}
	for _, test := range []struct {
		name      string
		links     []netlink.Link
		patterns  []string
		automatic map[int]string
		valid     bool
	}{
		{"unchanged", []netlink.Link{wan}, []string{"wan*"}, nil, true},
		{"wildcard added", []netlink.Link{wan, added}, []string{"wan*"}, nil, false},
		{"automatic added", []netlink.Link{wan, added}, nil, map[int]string{2: "wan0", 3: "wan1"}, false},
		{"automatic removed", []netlink.Link{wan, added}, nil, map[int]string{3: "wan1"}, false},
		{"unmanaged added", []netlink.Link{wan, added}, []string{"wan0"}, nil, true},
		{"wildcard excludes loopback", []netlink.Link{wan, &netlink.Dummy{Index: 1, Name: "lo"}}, []string{"*"}, nil, true},
		{"missing", nil, []string{"wan0"}, nil, false},
		{"header changed", []netlink.Link{&netlink.Dummy{Index: 2, Name: "wan0", EncapType: "none"}}, []string{"wan0"}, nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateReplacementInterfaces(descriptors, test.links, nil, test.patterns, test.automatic)
			if (err == nil) != test.valid {
				t.Fatalf("validation=%v, valid=%v", err, test.valid)
			}
		})
	}
}

func TestReplacementClaimKeepsInterfaceFreezeUntilReady(t *testing.T) {
	r := NewRuntime()
	defer r.Close()
	r.online = true
	r.current = &ControlPlane{}
	r.kernelLinks.privatePins, r.kernelLinks.preparing = true, true
	changed := errors.New("interception interfaces changed")
	r.kernelLinks.prepareErr = changed
	notified := false
	notify := func() error { notified = true; return nil }
	if err := r.ConfirmReady(notify); !errors.Is(err, changed) || notified {
		t.Fatalf("READY ignored a changed interface set: %v", err)
	}
	if !r.kernelLinks.privatePins || !r.kernelLinks.preparing {
		t.Fatal("failed READY released canonical ownership or interface freeze")
	}
	r.kernelLinks.prepareErr = nil
	if err := r.ConfirmReady(func() error { return context.Canceled }); !errors.Is(err, context.Canceled) || !r.kernelLinks.privatePins || !r.kernelLinks.preparing {
		t.Fatalf("failed notification granted ownership: %v", err)
	}
	if err := r.ConfirmReady(notify); err != nil || !notified {
		t.Fatal(err)
	}
	if r.kernelLinks.privatePins || r.kernelLinks.preparing {
		t.Fatal("READY did not grant normal pin and interface ownership")
	}
}

func TestReplacementSnapshotFreezeDoesNotHoldMutex(t *testing.T) {
	noopClose := func() error { return nil }
	r := NewRuntime()
	defer r.Close()
	r.kernelLinks.hostTCXLinks = []hostTCXLink{{linkIndex: 7, role: hostTCXLanIngress, close: noopClose}}
	r.kernelLinks.frozen = true
	snapshot := &ReplacementSnapshot{runtime: r, frozen: true}

	if !r.kernelLinks.mu.TryLock() {
		t.Fatal("active ReplacementSnapshot should not hold kernelLinks.mu")
	}
	r.kernelLinks.mu.Unlock()

	if r.kernelLinks.ownHostTCXLink(hostTCXLink{linkIndex: 8, role: hostTCXWanEgress, close: noopClose}) {
		t.Fatal("ownHostTCXLink mutated links while frozen")
	}
	if err := r.kernelLinks.closeHostTCXLinks(7); err != nil || len(r.kernelLinks.hostTCXLinks) != 1 {
		t.Fatalf("closeHostTCXLinks altered frozen attachments: err=%v len=%d", err, len(r.kernelLinks.hostTCXLinks))
	}
	if handled, err := r.kernelLinks.updateHostTCXLink(7, hostTCXProgram{role: hostTCXLanIngress}); !handled || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("updateHostTCXLink while frozen = (%v, %v), want (true, net.ErrClosed)", handled, err)
	}
	if err := r.kernelLinks.updatePrograms(new(bpfObjects), new(bpfObjects)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("updatePrograms while frozen = %v, want net.ErrClosed", err)
	}
	if err := r.kernelLinks.finishRebind(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("finishRebind while frozen = %v, want net.ErrClosed", err)
	}

	snapshot.Release()
	if r.kernelLinks.frozen {
		t.Fatal("Release did not clear kernelLinks.frozen")
	}
	if !r.kernelLinks.ownHostTCXLink(hostTCXLink{linkIndex: 8, role: hostTCXWanEgress, close: noopClose}) {
		t.Fatal("ownHostTCXLink stayed blocked after Release")
	}
}
