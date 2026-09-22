//go:build linux && dae_splice

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>

package splice

import "fmt"

const spliceFaultTarget = 1

type edgeState uint8

const (
	// Kernel-managed edges may drain passed bytes and arm redirection. A
	// backlog pause is temporary and can return to this state.
	edgeKernelManaged edgeState = iota
	edgePaused
	// Permanent fallback overrides a pause: draining -> userspace, never back
	// to kernel-managed. Draining waits for all in-flight redirects to finish.
	edgeDraining
	edgeUserspace
	edgeClosed // Source EOF has been propagated to the destination.
)

// spliceDirectEdge is one direction of a bidirectional relay. Pass mode sends
// bytes to userspace; an armed edge redirects them to dst in the kernel.
type spliceDirectEdge struct {
	src         TCPConn
	dst         TCPConn
	srcCookie   uint64
	dstCookie   uint64
	recordBytes func(uint64)
	activity    func()
	state       edgeState
}

func (edge *spliceDirectEdge) readyForUserspace() bool {
	return edge.state == edgeUserspace || edge.state == edgeClosed
}

type spliceEdgeSnapshot struct {
	endpoint bpf_spliceSpliceEndpoint
	source   bpf_spliceSpliceStats
	target   bpf_spliceSpliceStats
}

func (r *Runtime) edgeSnapshot(edge *spliceDirectEdge) (spliceEdgeSnapshot, error) {
	endpoint, err := r.endpoint(edge.srcCookie)
	if err != nil {
		return spliceEdgeSnapshot{}, err
	}
	source, err := r.stats(edge.srcCookie)
	if err != nil {
		return spliceEdgeSnapshot{}, err
	}
	snapshot := spliceEdgeSnapshot{endpoint: endpoint, source: source}
	if endpoint.PeerCookie != 0 {
		target, err := r.stats(edge.dstCookie)
		snapshot.target = target
		return snapshot, err
	}
	return snapshot, nil
}

func edgeNeedsDrain(snapshot *spliceEdgeSnapshot) bool {
	return snapshot.endpoint.PeerCookie == 0 || snapshot.source.SkbPass != snapshot.endpoint.Expected
}

func (r *Runtime) setPass(cookie uint64) error {
	endpoint, err := r.endpoint(cookie)
	if err != nil {
		return err
	}
	endpoint.PeerCookie = 0
	return r.updateEndpoint(cookie, &endpoint)
}

// armEdge enables redirection only while the pass counter still matches the
// pre-drain snapshot. Bytes arriving during the drain keep the edge in pass mode
// so that kernel-redirected bytes cannot overtake bytes queued for userspace.
func (r *Runtime) armEdge(edge *spliceDirectEdge, expected uint64) error {
	endpoint, err := r.endpoint(edge.srcCookie)
	if err != nil {
		return err
	}
	endpoint.PeerCookie = edge.dstCookie
	endpoint.Expected = expected
	return r.updateEndpoint(edge.srcCookie, &endpoint)
}

func (r *Runtime) pumpAndArm(edges [2]*spliceDirectEdge) error {
	allEmpty := true
	var expected [2]uint64
	for i, edge := range edges {
		stats, err := r.stats(edge.srcCookie)
		if err != nil {
			return err
		}
		expected[i] = stats.SkbPass
		eof, empty, err := drainTCP(edge.src, edge.dst, edge.recordBytes)
		if err != nil {
			return err
		}
		allEmpty = allEmpty && empty
		if eof {
			edge.state = edgeClosed
			if err := edge.dst.CloseWrite(); err != nil {
				return err
			}
		}
	}
	// An initial half-close keeps the surviving direction in userspace.
	for _, edge := range edges {
		if edge.state == edgeClosed {
			for _, remaining := range edges {
				if remaining.state != edgeClosed {
					remaining.state = edgeUserspace
				}
			}
			return nil
		}
	}
	if !allEmpty {
		return nil
	}
	for i, edge := range edges {
		if err := r.armEdge(edge, expected[i]); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runtime) handlePassEdge(edge *spliceDirectEdge, source bpf_spliceSpliceStats) error {
	eof, empty, err := drainTCP(edge.src, edge.dst, edge.recordBytes)
	if err != nil {
		return fmt.Errorf("drain splice edge %d -> %d: %w", edge.srcCookie, edge.dstCookie, err)
	}
	if eof {
		edge.state = edgeClosed
		return edge.dst.CloseWrite()
	}
	if !empty {
		return nil
	}
	return r.armEdge(edge, source.SkbPass)
}

// edgeQuiescent checks both sides of the handoff: no verdict is in flight and
// the destination has accepted all redirected bytes. Read the source twice to
// detect a redirect racing the destination counter read.
func (r *Runtime) edgeQuiescent(edge *spliceDirectEdge) (bpf_spliceSpliceStats, bool, error) {
	before, err := r.stats(edge.srcCookie)
	if err != nil {
		return bpf_spliceSpliceStats{}, false, err
	}
	target, err := r.stats(edge.dstCookie)
	if err != nil {
		return bpf_spliceSpliceStats{}, false, err
	}
	after, err := r.stats(edge.srcCookie)
	if err != nil {
		return bpf_spliceSpliceStats{}, false, err
	}
	if err := edge.checkFault(after); err != nil {
		return after, false, err
	}
	if before.SkbActive != 0 || after.SkbActive != 0 ||
		before.SkbRedirected != after.SkbRedirected ||
		target.EgressAccepted < after.SkbRedirected {
		return after, false, nil
	}
	return after, true, nil
}

// A missing redirect target can fall back to userspace; other kernel faults
// terminate the session because delivery can no longer be guaranteed.
func (edge *spliceDirectEdge) checkFault(stats bpf_spliceSpliceStats) error {
	if fault := stats.Fault &^ spliceFaultTarget; fault != 0 {
		return fmt.Errorf("splice endpoint %d fault %d", edge.srcCookie, fault)
	}
	return nil
}

func (r *Runtime) requestUserspace(edge *spliceDirectEdge) error {
	switch edge.state {
	case edgeDraining, edgeUserspace, edgeClosed:
		return nil
	}
	if err := r.setPass(edge.srcCookie); err != nil {
		return err
	}
	edge.state = edgeDraining
	return nil
}

func (r *Runtime) requestUserspaceRelay(edges [2]*spliceDirectEdge) error {
	for _, edge := range edges {
		if err := r.requestUserspace(edge); err != nil {
			return err
		}
	}
	return nil
}
