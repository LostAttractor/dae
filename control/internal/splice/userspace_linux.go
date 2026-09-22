//go:build linux && dae_splice

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>

package splice

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

const maxDrainBytes = 512 * 1024

func writeFullAndRecord(writer io.Writer, p []byte, recordBytes func(uint64)) error {
	for len(p) > 0 {
		n, err := writer.Write(p)
		if n > 0 {
			if recordBytes != nil {
				recordBytes(uint64(n))
			}
			p = p[n:]
		}
		if err != nil {
			return connectionFailure(writer, netproxy.OpWrite, err)
		}
		if n == 0 {
			return connectionFailure(writer, netproxy.OpWrite, io.ErrShortWrite)
		}
	}
	return nil
}

func connectionFailure(conn any, phase netproxy.Operation, err error) error {
	if wrapper, ok := conn.(interface {
		WrapFailure(error, netproxy.Operation) error
	}); ok {
		return wrapper.WrapFailure(err, phase)
	}
	return netproxy.WrapFailure(err, netproxy.Failure{Phase: phase})
}

// Errors from maps, epoll, and accounting are local runtime failures. Socket
// operations already carry endpoint provenance and must retain it.
func runtimeFailure(err error) error {
	var causes []error
	for _, failure := range netproxy.Failures(err) {
		if failure.Origin == "" || failure.Origin == netproxy.OriginUnknown {
			failure.Origin = netproxy.OriginLocalProtocol
			failure.Scope = netproxy.ScopeOperation
		}
		causes = append(causes, &failure)
	}
	return errors.Join(causes...)
}

// drainTCP forwards bytes already queued in pass mode. A short read deadline
// detects an empty queue; the byte budget keeps one busy direction from starving
// the other. Hitting that budget is not evidence that the queue is empty.
func drainTCP(src, dst net.Conn, recordBytes func(uint64)) (eof, empty bool, err error) {
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
			if err := writeFullAndRecord(dst, buf[:read], recordBytes); err != nil {
				return false, false, err
			}
			drained += read
		}
		if readErr == nil {
			continue
		}
		if readErr == io.EOF { // Wrapped failures must retain their provenance.
			return true, true, nil
		}
		if netErr, ok := errors.AsType[net.Error](readErr); ok && netErr.Timeout() {
			return false, true, nil
		}
		return false, false, readErr
	}
	return false, false, nil
}

// copyUserspace runs after an edge has permanently left kernel redirection.
// A clean EOF propagates FIN; the coordinator handles failures by closing both
// endpoints so reads and writes in the reverse direction are interrupted.
func (edge *spliceDirectEdge) copyUserspace(idleTimeout time.Duration) error {
	buf := make([]byte, 32*1024)
	for {
		if err := edge.src.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
			return err
		}
		n, err := edge.src.Read(buf)
		if n > 0 {
			if err := edge.dst.SetWriteDeadline(time.Now().Add(idleTimeout)); err != nil {
				return err
			}
			if err := writeFullAndRecord(edge.dst, buf[:n], edge.recordBytes); err != nil {
				return err
			}
		}
		if err == io.EOF { // Only a read EOF permits a graceful half-close.
			return edge.dst.CloseWrite()
		}
		if err != nil {
			return err
		}
	}
}

func (r *Runtime) relayUserspace(edges [2]*spliceDirectEdge) error {
	// Both workers can report without blocking, leaving connection cleanup to
	// this coordinator even when the opposite worker is stuck in Write.
	results := make(chan error, len(edges))
	active := 0
	for _, edge := range edges {
		if edge.state == edgeClosed {
			continue
		}
		active++
		go func() { results <- edge.copyUserspace(r.idleTimeout) }()
	}
	var combined error
	stopped := false
	for range active {
		err := <-results
		if err != nil && !stopped {
			stopped = true
			// Interrupt the opposite direction even when it is blocked writing
			// to this direction's source rather than reading its destination.
			// The two sources are the session's two distinct connections.
			for _, edge := range edges {
				_ = edge.src.Close()
			}
		}
		for _, failure := range netproxy.Failures(err) {
			if failure.Origin != netproxy.OriginLocalCleanup {
				combined = errors.Join(combined, &failure)
			}
		}
	}
	return combined
}
