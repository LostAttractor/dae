//go:build linux && dae_splice && dae_splice_tests

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>

package splice

import (
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestSplicePausedEdgeHandoffIntegration(t *testing.T) {
	for _, action := range []string{"resume", "half_close", "target_fault"} {
		t.Run(action, func(t *testing.T) {
			runtime := loadTestSpliceRuntime(t)
			client, accepted := tcpPair(t)
			remote, server := tcpPair(t)
			defer client.Close()
			defer accepted.Close()
			defer remote.Close()
			defer server.Close()
			acceptedCookie, err := runtime.registerSocket(accepted)
			if err != nil {
				t.Fatal(err)
			}
			defer runtime.cleanupMetadata(acceptedCookie)
			remoteCookie, err := runtime.registerSocket(remote)
			if err != nil {
				t.Fatal(err)
			}
			defer runtime.cleanupMetadata(remoteCookie)
			edges := [2]*spliceDirectEdge{
				{src: accepted, dst: remote, srcCookie: acceptedCookie, dstCookie: remoteCookie},
				{src: remote, dst: accepted, srcCookie: remoteCookie, dstCookie: acceptedCookie},
			}
			if err := runtime.pumpAndArm(edges); err != nil {
				t.Fatal(err)
			}

			// Seed a backlog to exercise the real fuse and handoff against BPF
			// maps without relying on timing a 64 MiB transfer to a slow peer.
			const backlog = 64 * 1024 * 1024
			source := bpf_spliceSpliceStats{SkbRedirected: backlog}
			storeStats := func(cookie uint64, stats bpf_spliceSpliceStats) {
				t.Helper()
				if err := runtime.objects.SpliceStats.Update(&cookie, &stats, ebpf.UpdateExist); err != nil {
					t.Fatal(err)
				}
			}
			storeStats(acceptedCookie, source)
			session := directSession{runtime: runtime, edges: edges, lastProgress: time.Now()}
			if err := session.pollEdge(0); err != nil {
				t.Fatal(err)
			}
			if edges[0].state != edgePaused {
				t.Fatalf("backlog did not pause upload: state=%v", edges[0].state)
			}

			fallback := action != "resume"
			switch action {
			case "half_close":
				// A FIN from the opposite direction also retires the paused edge.
				if err := session.handleEvent(unix.EpollEvent{Fd: 1, Events: unix.EPOLLRDHUP}); err != nil {
					t.Fatal(err)
				}
			case "target_fault":
				source.Fault = spliceFaultTarget
				storeStats(acceptedCookie, source)
				if err := session.pollEdge(0); err != nil {
					t.Fatal(err)
				}
			}
			assertWaiting := func() {
				t.Helper()
				if err := session.pollEdge(0); err != nil {
					t.Fatal(err)
				}
				endpoint, err := runtime.endpoint(acceptedCookie)
				if err != nil {
					t.Fatal(err)
				}
				if endpoint.PeerCookie != 0 || edges[0].readyForUserspace() {
					t.Fatalf("handoff overtook in-flight redirects: state=%v endpoint=%+v", edges[0].state, endpoint)
				}
			}
			assertWaiting() // The destination has not accepted the backlog yet.
			storeStats(remoteCookie, bpf_spliceSpliceStats{EgressAccepted: backlog})
			source.SkbActive = 1
			storeStats(acceptedCookie, source)
			assertWaiting() // Accepted bytes alone do not rule out an active verdict.
			source.SkbActive = 0
			storeStats(acceptedCookie, source)

			// Repeat polling after the handoff to ensure userspace edges stay in
			// pass mode while waiting for the reverse direction to become ready.
			for range 2 {
				for i, edge := range edges {
					if err := session.pollEdge(i); err != nil {
						t.Fatal(err)
					}
					endpoint, err := runtime.endpoint(edge.srcCookie)
					if err != nil {
						t.Fatal(err)
					}
					wantState, wantPeer := edgeKernelManaged, edge.dstCookie
					if fallback {
						wantState, wantPeer = edgeUserspace, 0
					}
					if edge.state != wantState || endpoint.PeerCookie != wantPeer {
						t.Fatalf("handoff edge %d: state=%v peer=%d, want state=%v peer=%d", i, edge.state, endpoint.PeerCookie, wantState, wantPeer)
					}
				}
			}

			var done chan error
			if fallback {
				done = make(chan error, 1)
				go func() { done <- runtime.relayUserspace(edges) }()
			}
			upload, download := []byte("upload after handoff"), []byte("download after handoff")
			if err := writeFull(client, upload); err != nil {
				t.Fatal(err)
			}
			readExactly(t, server, upload)
			if err := writeFull(server, download); err != nil {
				t.Fatal(err)
			}
			readExactly(t, client, download)
			stats, err := runtime.stats(acceptedCookie)
			if err != nil {
				t.Fatal(err)
			}
			if fallback {
				if stats.SkbRedirected != backlog || stats.SkbPass < uint64(len(upload)) {
					t.Fatalf("fallback resumed kernel redirection: %+v", stats)
				}
				if err := client.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if err := server.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				waitRelay(t, done)
			} else if stats.SkbRedirected != backlog+uint64(len(upload)) {
				t.Fatalf("temporary pause did not resume kernel redirection: %+v", stats)
			}
		})
	}
}
