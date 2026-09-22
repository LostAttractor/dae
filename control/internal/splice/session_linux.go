//go:build linux && dae_splice

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>

package splice

import (
	"errors"
	"fmt"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/sys/unix"
)

// directSession coordinates the two edges on one goroutine until both can be
// handed to userspace. Epoll observes socket shutdown/errors; BPF counters track
// redirect progress and determine when a handoff preserves byte ordering.
type directSession struct {
	runtime      *Runtime
	edges        [2]*spliceDirectEdge
	edgeCounters [2]uint64
	lastProgress time.Time
}

func (r *Runtime) runDirectSession(edges [2]*spliceDirectEdge) error {
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return err
	}
	defer unix.Close(epfd)
	edgeFDs, err := watchEdges(epfd, edges)
	if err != nil {
		return err
	}

	session := directSession{runtime: r, edges: edges, lastProgress: time.Now()}
	events := make([]unix.EpollEvent, len(edges))
	for {
		n, err := unix.EpollWait(epfd, events, 1000)
		if err != nil && !errors.Is(err, unix.EINTR) {
			return err
		}
		for i := range n {
			if err := session.handleEvent(events[i]); err != nil {
				return err
			}
		}
		for i := range edges {
			if err := session.pollEdge(i); err != nil {
				return err
			}
		}
		for i, edge := range edges {
			if edge.state == edgeClosed && edgeFDs[i] >= 0 {
				_ = unix.EpollCtl(epfd, unix.EPOLL_CTL_DEL, edgeFDs[i], nil)
				edgeFDs[i] = -1
			}
		}
		if edges[0].state == edgeClosed && edges[1].state == edgeClosed {
			return nil
		}
		if edges[0].readyForUserspace() && edges[1].readyForUserspace() {
			return r.relayUserspace(edges)
		}
		if time.Since(session.lastProgress) >= r.idleTimeout {
			return nil
		}
	}
}

// watchEdges stores the edge index in each event, and retains the actual file
// descriptors separately so closed directions can be removed from epoll.
func watchEdges(epfd int, edges [2]*spliceDirectEdge) ([2]int, error) {
	edgeFDs := [2]int{-1, -1}
	for i, edge := range edges {
		if edge.state == edgeClosed {
			continue
		}
		raw, err := edge.src.SyscallConn()
		if err != nil {
			return edgeFDs, err
		}
		var controlErr error
		if err := raw.Control(func(rawFD uintptr) {
			fd := int(rawFD)
			event := &unix.EpollEvent{
				Events: unix.EPOLLIN | unix.EPOLLRDHUP | unix.EPOLLHUP | unix.EPOLLERR,
				Fd:     int32(i),
			}
			controlErr = unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, fd, event)
			if controlErr == nil {
				edgeFDs[i] = fd
			}
		}); err != nil {
			return edgeFDs, err
		}
		if controlErr != nil {
			return edgeFDs, controlErr
		}
	}
	return edgeFDs, nil
}

func (s *directSession) handleEvent(event unix.EpollEvent) error {
	edge := s.edges[int(event.Fd)]
	if event.Events&unix.EPOLLERR != 0 {
		socketErr, err := tcpSocketError(edge.src)
		if err != nil {
			return connectionFailure(edge.src, netproxy.OpRead, fmt.Errorf("splice socket error: %w", err))
		}
		switch unix.Errno(socketErr) {
		case 0:
		case unix.EPIPE, unix.ECONNRESET:
			if err := s.runtime.requestUserspaceRelay(s.edges); err != nil {
				return err
			}
		default:
			return connectionFailure(edge.src, netproxy.OpRead, fmt.Errorf("splice socket error: %w", unix.Errno(socketErr)))
		}
	}
	if event.Events&(unix.EPOLLRDHUP|unix.EPOLLHUP) != 0 && edge.state != edgeClosed {
		return s.runtime.requestUserspaceRelay(s.edges)
	}
	return nil
}

func (s *directSession) pollEdge(index int) error {
	r, edge := s.runtime, s.edges[index]
	switch edge.state {
	case edgeClosed, edgeUserspace:
		// Completed handoffs only observe counters while waiting for the other
		// direction. They must never drain or rearm kernel redirection.
		stats, err := r.stats(edge.srcCookie)
		if err != nil {
			return err
		}
		if err := edge.checkFault(stats); err != nil {
			return err
		}
		s.observeProgress(index, stats)
		return nil
	case edgeDraining, edgePaused:
		// Both transitions wait for outstanding redirects. Only a temporary
		// backlog pause may return to kernel redirection.
		source, ready, err := r.edgeQuiescent(edge)
		if err != nil {
			return err
		}
		s.observeProgress(index, source)
		if edge.state == edgePaused && source.Fault&spliceFaultTarget != 0 {
			return r.requestUserspaceRelay(s.edges)
		}
		if !ready {
			return nil
		}
		if edge.state == edgePaused {
			edge.state = edgeKernelManaged
			return r.handlePassEdge(edge, source)
		}
		edge.state = edgeUserspace
		return nil
	}

	// Only kernel-managed edges reach this point.
	snapshot, err := r.edgeSnapshot(edge)
	if err != nil {
		return err
	}
	if err := edge.checkFault(snapshot.source); err != nil {
		return err
	}
	if snapshot.source.Fault&spliceFaultTarget != 0 {
		return r.requestUserspaceRelay(s.edges)
	}
	s.observeProgress(index, snapshot.source)
	// Pause before draining passed bytes so they cannot overtake the backlog.
	const highWatermark = 64 * 1024 * 1024
	if snapshot.endpoint.PeerCookie != 0 && snapshot.source.SkbRedirected > snapshot.target.EgressAccepted &&
		snapshot.source.SkbRedirected-snapshot.target.EgressAccepted >= highWatermark {
		if err := r.setPass(edge.srcCookie); err != nil {
			return err
		}
		edge.state = edgePaused
		return nil
	}
	if edgeNeedsDrain(&snapshot) {
		return r.handlePassEdge(edge, snapshot.source)
	}
	return nil
}

func (s *directSession) observeProgress(index int, stats bpf_spliceSpliceStats) {
	counter := stats.SkbPass + stats.SkbRedirected + stats.EgressAccepted
	if counter == s.edgeCounters[index] {
		return
	}
	s.edgeCounters[index] = counter
	s.lastProgress = time.Now()
	if activity := s.edges[index].activity; activity != nil {
		activity()
	}
}
