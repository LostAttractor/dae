//go:build linux && dae_splice

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>

package splice

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	"golang.org/x/sys/unix"
)

var minimumSpliceKernelVersion = internal.Version{6, 18, 0}

type Runtime struct {
	objects     bpf_spliceObjects
	links       []link.Link
	idleTimeout time.Duration
	mu          sync.Mutex
	sessions    int
	closing     bool
	closeErr    error
}

func (r *Runtime) beginSession() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing {
		return false
	}
	r.sessions++
	return true
}

func (r *Runtime) endSession() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions--
	if r.closing && r.sessions == 0 {
		r.closeLocked()
	}
}

func (r *Runtime) closeLocked() {
	for i := len(r.links) - 1; i >= 0; i-- {
		r.closeErr = errors.Join(r.closeErr, r.links[i].Close())
	}
	r.links = nil
	r.closeErr = errors.Join(r.closeErr, r.objects.Close())
}

const (
	spliceFaultTarget = 1
	maxDrainBytes     = 512 * 1024
)

func tcpSocketError(conn *net.TCPConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var socketErr int
	var controlErr error
	if err := raw.Control(func(rawFD uintptr) {
		socketErr, controlErr = unix.GetsockoptInt(int(rawFD), unix.SOL_SOCKET, unix.SO_ERROR)
	}); err != nil {
		return 0, err
	}
	return socketErr, controlErr
}

func spliceSocketEligible(conn *net.TCPConn) bool {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	protocol := 0
	var controlErr error
	if err := raw.Control(func(rawFD uintptr) {
		protocol, controlErr = unix.GetsockoptInt(int(rawFD), unix.SOL_SOCKET, unix.SO_PROTOCOL)
	}); err != nil {
		return false
	}
	return controlErr == nil && protocol != unix.IPPROTO_MPTCP
}

func (r *Runtime) endpoint(cookie uint64) (bpf_spliceSpliceEndpoint, error) {
	var endpoint bpf_spliceSpliceEndpoint
	err := r.objects.SpliceEndpoints.Lookup(&cookie, &endpoint)
	return endpoint, err
}

func (r *Runtime) stats(cookie uint64) (bpf_spliceSpliceStats, error) {
	var stats bpf_spliceSpliceStats
	err := r.objects.SpliceStats.Lookup(&cookie, &stats)
	return stats, err
}

func (r *Runtime) updateEndpoint(cookie uint64, endpoint *bpf_spliceSpliceEndpoint) error {
	return r.objects.SpliceEndpoints.Update(&cookie, endpoint, ebpf.UpdateExist)
}

func (r *Runtime) cleanupMetadata(cookies ...uint64) {
	for _, cookie := range cookies {
		_ = r.objects.SpliceSocks.Delete(&cookie)
		_ = r.objects.SpliceEndpoints.Delete(&cookie)
		_ = r.objects.SpliceStats.Delete(&cookie)
	}
}

func (r *Runtime) registerSocket(conn *net.TCPConn) (uint64, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cookie uint64
	var controlErr error
	if err := raw.Control(func(rawFD uintptr) {
		fd := int(rawFD)
		cookie, controlErr = unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
		if controlErr != nil {
			return
		}
		endpoint := bpf_spliceSpliceEndpoint{}
		if updateErr := r.objects.SpliceEndpoints.Update(&cookie, &endpoint, ebpf.UpdateNoExist); updateErr != nil {
			controlErr = fmt.Errorf("store splice endpoint: %w", updateErr)
			return
		}
		stats := bpf_spliceSpliceStats{}
		if updateErr := r.objects.SpliceStats.Update(&cookie, &stats, ebpf.UpdateNoExist); updateErr != nil {
			_ = r.objects.SpliceEndpoints.Delete(&cookie)
			controlErr = fmt.Errorf("store splice stats: %w", updateErr)
			return
		}
		value := uint64(fd)
		if updateErr := r.objects.SpliceSocks.Update(&cookie, &value, ebpf.UpdateNoExist); updateErr != nil {
			_ = r.objects.SpliceStats.Delete(&cookie)
			_ = r.objects.SpliceEndpoints.Delete(&cookie)
			controlErr = fmt.Errorf("register socket in splice sockhash: %w", updateErr)
		}
	}); err != nil {
		return 0, err
	}
	return cookie, controlErr
}

func writeFull(conn *net.TCPConn, p []byte) error {
	for len(p) > 0 {
		n, err := conn.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func drainTCP(src, dst *net.TCPConn) (eof, empty bool, err error) {
	buf := make([]byte, 32*1024)
	defer src.SetReadDeadline(time.Time{})
	defer dst.SetWriteDeadline(time.Time{})
	drained := 0
	for drained < maxDrainBytes {
		if err := src.SetReadDeadline(time.Now().Add(2 * time.Millisecond)); err != nil {
			return false, false, err
		}
		read, readErr := src.Read(buf)
		if read > 0 {
			if err := dst.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return false, false, err
			}
			if err := writeFull(dst, buf[:read]); err != nil {
				return false, false, err
			}
			drained += read
		}
		if readErr == nil {
			continue
		}
		if errors.Is(readErr, io.EOF) {
			return true, true, nil
		}
		var netErr net.Error
		if errors.As(readErr, &netErr) && netErr.Timeout() {
			return false, true, nil
		}
		return false, false, readErr
	}
	return false, false, nil
}

func (r *Runtime) setPass(cookie uint64) error {
	endpoint, err := r.endpoint(cookie)
	if err != nil {
		return err
	}
	endpoint.PeerCookie = 0
	return r.updateEndpoint(cookie, &endpoint)
}

type spliceDirectEdge struct {
	src              *net.TCPConn
	dst              *net.TCPConn
	srcCookie        uint64
	dstCookie        uint64
	userspace        bool
	userspacePending bool
	paused           bool
	closed           bool
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
	if edge.paused || endpoint.PeerCookie != 0 {
		target, err := r.stats(edge.dstCookie)
		snapshot.target = target
		return snapshot, err
	}
	return snapshot, nil
}

func edgeNeedsDrain(snapshot *spliceEdgeSnapshot) bool {
	if snapshot.endpoint.PeerCookie != 0 {
		return snapshot.source.SkbPass != snapshot.endpoint.Expected
	}
	return true
}

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
	empty := true
	var expected [2]uint64
	for i, edge := range edges {
		stats, err := r.stats(edge.srcCookie)
		if err != nil {
			return err
		}
		expected[i] = stats.SkbPass
		eof, drained, err := drainTCP(edge.src, edge.dst)
		if err != nil {
			return err
		}
		empty = empty && drained
		if eof {
			edge.closed = true
			_ = edge.dst.CloseWrite()
		}
	}
	for _, edge := range edges {
		if edge.closed {
			for _, remaining := range edges {
				if !remaining.closed {
					remaining.userspace = true
				}
			}
			return nil
		}
	}
	if !empty {
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
	eof, empty, err := drainTCP(edge.src, edge.dst)
	if err != nil {
		return fmt.Errorf("drain splice edge %d -> %d: %w", edge.srcCookie, edge.dstCookie, err)
	}
	if eof {
		edge.closed = true
		return edge.dst.CloseWrite()
	}
	if !empty {
		return nil
	}
	return r.armEdge(edge, source.SkbPass)
}

func (r *Runtime) edgeQuiescent(edge *spliceDirectEdge) (
	bpf_spliceSpliceStats, bool, error,
) {
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
	if fault := after.Fault &^ spliceFaultTarget; fault != 0 {
		return after, false, fmt.Errorf("splice endpoint %d fault %d", edge.srcCookie, fault)
	}
	if before.SkbActive != 0 || after.SkbActive != 0 ||
		before.SkbRedirected != after.SkbRedirected ||
		target.EgressAccepted < after.SkbRedirected {
		return after, false, nil
	}
	return after, true, nil
}

func (r *Runtime) requestUserspace(edge *spliceDirectEdge) error {
	if edge.userspace || edge.userspacePending {
		return nil
	}
	if err := r.setPass(edge.srcCookie); err != nil {
		return err
	}
	edge.userspacePending = true
	return nil
}

func (r *Runtime) requestUserspaceRelay(edges [2]*spliceDirectEdge) error {
	for _, edge := range edges {
		if !edge.closed {
			if err := r.requestUserspace(edge); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Runtime) updateFuse(edge *spliceDirectEdge, snapshot *spliceEdgeSnapshot) (bool, error) {
	if !edge.paused && snapshot.endpoint.PeerCookie == 0 {
		return false, nil
	}
	const highWatermark = 64 * 1024 * 1024
	backlog := uint64(0)
	if snapshot.source.SkbRedirected > snapshot.target.EgressAccepted {
		backlog = snapshot.source.SkbRedirected - snapshot.target.EgressAccepted
	}
	if !edge.paused && backlog >= highWatermark {
		if err := r.setPass(edge.srcCookie); err != nil {
			return false, err
		}
		edge.paused = true
		return true, nil
	}
	if !edge.paused {
		return false, nil
	}
	source, ready, err := r.edgeQuiescent(edge)
	if err != nil {
		return false, err
	}
	if !ready {
		return false, nil
	}
	edge.paused = false
	return true, r.handlePassEdge(edge, source)
}

func progressCounter(stats bpf_spliceSpliceStats) uint64 {
	return stats.SkbPass + stats.SkbRedirected + stats.EgressAccepted
}

func (r *Runtime) relayUserspace(edges [2]*spliceDirectEdge) error {
	results := make(chan error, len(edges))
	active := 0
	for _, edge := range edges {
		if edge.closed {
			continue
		}
		active++
		go func() {
			buf := make([]byte, 32*1024)
			for {
				if err := edge.src.SetReadDeadline(time.Now().Add(r.idleTimeout)); err != nil {
					_ = edge.dst.Close()
					results <- err
					return
				}
				n, err := edge.src.Read(buf)
				if n > 0 {
					if writeErr := edge.dst.SetWriteDeadline(time.Now().Add(r.idleTimeout)); writeErr != nil {
						_ = edge.dst.Close()
						results <- writeErr
						return
					}
					if writeErr := writeFull(edge.dst, buf[:n]); writeErr != nil {
						_ = edge.dst.Close()
						results <- writeErr
						return
					}
				}
				if err == nil {
					continue
				}
				if errors.Is(err, io.EOF) {
					err = edge.dst.CloseWrite()
					if err != nil {
						_ = edge.dst.Close()
					}
				} else {
					_ = edge.dst.Close()
				}
				results <- err
				return
			}
		}()
	}
	var first error
	for range active {
		if err := <-results; first == nil {
			first = err
		}
	}
	return first
}

func (r *Runtime) runDirectSession(edges [2]*spliceDirectEdge) error {
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return err
	}
	defer unix.Close(epfd)
	edgeFDs := [2]int{-1, -1}
	for i, edge := range edges {
		if edge.closed {
			continue
		}
		raw, err := edge.src.SyscallConn()
		if err != nil {
			return err
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
			return err
		}
		if controlErr != nil {
			return controlErr
		}
	}

	events := make([]unix.EpollEvent, len(edges))
	lastProgress := time.Now()
	var edgeCounters [2]uint64
	for {
		n, err := unix.EpollWait(epfd, events, 1000)
		if err != nil && !errors.Is(err, unix.EINTR) {
			return err
		}
		for i := 0; i < n; i++ {
			event := events[i]
			edgeIndex := int(event.Fd)
			edge := edges[edgeIndex]
			if event.Events&unix.EPOLLERR != 0 {
				soErr, getsockoptErr := tcpSocketError(edge.src)
				if getsockoptErr != nil {
					return fmt.Errorf("splice socket error: %w", getsockoptErr)
				}
				if soErr != 0 {
					if soErr == int(unix.EPIPE) || soErr == int(unix.ECONNRESET) {
						if err := r.requestUserspaceRelay(edges); err != nil {
							return err
						}
					} else {
						return fmt.Errorf("splice socket error: %w", unix.Errno(soErr))
					}
				}
			}
			if event.Events&(unix.EPOLLRDHUP|unix.EPOLLHUP) != 0 && !edge.closed {
				if err := r.requestUserspaceRelay(edges); err != nil {
					return err
				}
			}
		}
		for i, edge := range edges {
			if edge.closed {
				stats, err := r.stats(edge.srcCookie)
				if err != nil {
					return err
				}
				if fault := stats.Fault &^ spliceFaultTarget; fault != 0 {
					return fmt.Errorf("splice endpoint %d fault %d", edge.srcCookie, fault)
				}
				counter := progressCounter(stats)
				if counter != edgeCounters[i] {
					edgeCounters[i] = counter
					lastProgress = time.Now()
				}
				continue
			}
			if edge.userspacePending {
				_, ready, err := r.edgeQuiescent(edge)
				if err != nil {
					return err
				}
				if !ready {
					continue
				}
				edge.userspacePending = false
				edge.userspace = true
			}
			snapshot, err := r.edgeSnapshot(edge)
			if err != nil {
				return err
			}
			if fault := snapshot.source.Fault &^ spliceFaultTarget; fault != 0 {
				return fmt.Errorf("splice endpoint %d fault %d", edge.srcCookie, fault)
			}
			if snapshot.source.Fault&spliceFaultTarget != 0 &&
				!edge.userspace && !edge.userspacePending {
				if err := r.requestUserspaceRelay(edges); err != nil {
					return err
				}
				continue
			}
			counter := progressCounter(snapshot.source)
			if counter != edgeCounters[i] {
				edgeCounters[i] = counter
				lastProgress = time.Now()
			}
			transitioned, err := r.updateFuse(edge, &snapshot)
			if err != nil {
				return err
			}
			if transitioned || edge.paused {
				continue
			}
			if edge.userspace {
				continue
			}
			if edgeNeedsDrain(&snapshot) {
				if err := r.handlePassEdge(edge, snapshot.source); err != nil {
					return err
				}
				continue
			}
		}
		for i, edge := range edges {
			if edge.closed && edgeFDs[i] >= 0 {
				_ = unix.EpollCtl(epfd, unix.EPOLL_CTL_DEL, edgeFDs[i], nil)
				edgeFDs[i] = -1
			}
		}
		if edges[0].closed && edges[1].closed {
			return nil
		}
		if (edges[0].closed || edges[0].userspace) &&
			(edges[1].closed || edges[1].userspace) {
			return r.relayUserspace(edges)
		}
		if time.Since(lastProgress) >= r.idleTimeout {
			return nil
		}
	}
}

func (r *Runtime) Relay(acceptedConn, remoteConn *net.TCPConn) (handled bool, err error) {
	if !r.beginSession() {
		return false, nil
	}
	defer r.endSession()
	if !spliceSocketEligible(acceptedConn) || !spliceSocketEligible(remoteConn) {
		return false, nil
	}

	cookieA, err := r.registerSocket(acceptedConn)
	if err != nil {
		return false, nil
	}
	cookieR, err := r.registerSocket(remoteConn)
	if err != nil {
		r.cleanupMetadata(cookieA)
		return false, nil
	}
	defer r.cleanupMetadata(cookieA, cookieR)
	edges := [2]*spliceDirectEdge{
		{
			src: acceptedConn, dst: remoteConn,
			srcCookie: cookieA, dstCookie: cookieR,
		},
		{
			src: remoteConn, dst: acceptedConn,
			srcCookie: cookieR, dstCookie: cookieA,
		},
	}
	if err := r.pumpAndArm(edges); err != nil {
		_ = r.setPass(cookieA)
		_ = r.setPass(cookieR)
		return true, err
	}
	return true, r.runDirectSession(edges)
}

func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closing {
		r.closing = true
		if r.sessions == 0 {
			r.closeLocked()
		}
	}
	return r.closeErr
}

func New(opts *ebpf.CollectionOptions, idleTimeout time.Duration) (_ *Runtime, err error) {
	kernelVersion, err := internal.KernelVersion()
	if err != nil {
		return nil, fmt.Errorf("detect kernel version: %w", err)
	}
	if kernelVersion.Less(minimumSpliceKernelVersion) {
		return nil, nil
	}

	spec, err := loadBpf_splice()
	if err != nil {
		return nil, fmt.Errorf("load splice collection spec: %w", err)
	}
	runtime := &Runtime{idleTimeout: idleTimeout}
	defer func() {
		if err != nil {
			_ = runtime.Close()
		}
	}()
	if err = spec.LoadAndAssign(&runtime.objects, opts); err != nil {
		return nil, fmt.Errorf("load splice objects: %w", err)
	}

	skbLink, err := link.AttachRawLink(link.RawLinkOptions{
		Target:  runtime.objects.SpliceSocks.FD(),
		Program: runtime.objects.SpliceStreamVerdict,
		Attach:  ebpf.AttachSkSKBStreamVerdict,
	})
	if err != nil {
		return nil, fmt.Errorf("attach splice SK_SKB verdict: %w", err)
	}
	runtime.links = append(runtime.links, skbLink)

	for _, tracing := range []struct {
		name    string
		program *ebpf.Program
	}{
		{"SK_SKB fault", runtime.objects.SpliceAccountSkbFault},
		{"egress", runtime.objects.SpliceAccountEgress},
	} {
		tracingLink, err := link.AttachTracing(link.TracingOptions{Program: tracing.program})
		if err != nil {
			return nil, fmt.Errorf("attach splice %s accounting: %w", tracing.name, err)
		}
		runtime.links = append(runtime.links, tracingLink)
	}

	return runtime, nil
}
