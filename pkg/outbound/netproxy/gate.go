package netproxy

import (
	"net"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// A gated carrier's kernel socket keeps at most about UnsentTime of
	// unsent bytes at the carrier's rate, and no less than MinUnsent.
	MinUnsent  = 16 << 10
	UnsentTime = 6 * time.Millisecond
	// MaxUnit is the batch of a carrier without a socket to gate: its kernel
	// queue is long anyway, and a larger batch only saves CPU.
	MaxUnit = 32 << 10
	// gateWindow is how often the gate judges who holds the pace.
	gateWindow = 50 * time.Millisecond
)

var gateWaits atomic.Uint64

// GateWaits counts the times a carrier writer waited at its gate.
func GateWaits() uint64 { return gateWaits.Load() }

// CarrierGate keeps the bytes a shared carrier's kernel socket has not sent
// below a limit L that lasts about UnsentTime at the carrier's rate, so that
// what is sent next waits above it, where a scheduler tells flows apart,
// instead of behind a long kernel queue. The writer calls Wait before each
// batch of Unit bytes, L/2: TCP_NOTSENT_LOWAT is L, and the socket polls
// writable only below L/2 (tcp_poll), so a batch takes it to at most L.
// Without a TCP socket under the carrier the gate does nothing. It is not
// safe for concurrent use.
type CarrierGate struct {
	raw    syscall.RawConn // nil: no socket to gate
	sndbuf int
	lowat  int // as set on the socket
	unsent int // L
	// floor rises while the writer, not the carrier, holds the pace: a
	// writer slower than its batch lasts would see the carrier's rate
	// shrink with L, down to MinUnsent.
	floor         float64
	window        time.Time
	passes, waits int
}

// NewCarrierGate gates the TCP socket that conn's writes go to (see
// SendSocket), if any.
func NewCarrierGate(conn net.Conn) *CarrierGate {
	g := &CarrierGate{unsent: MinUnsent}
	if tcp := SendSocket(conn); tcp != nil {
		if raw, err := tcp.SyscallConn(); err == nil && setUnsentLowat(raw, MinUnsent) == nil {
			g.raw, g.lowat, g.sndbuf = raw, MinUnsent, sendBuffer(raw)
		}
	}
	return g
}

// Wait returns once the socket polls writable. busy reports a writer with
// more queued than its last batch: only then does a pass without waiting
// show that the writer holds the pace.
func (g *CarrierGate) Wait(busy bool) error {
	if g.raw == nil {
		return nil
	}
	waited, err := waitWritable(g.raw)
	if waited {
		gateWaits.Add(1)
	}
	if busy {
		g.passes++
		if waited {
			g.waits++
		}
	}
	return err
}

// Adjust sets L from rate, the bytes per second the carrier took while
// frames waited for it: L = clamp(max(UnsentTime × rate, floor), MinUnsent,
// SO_SNDBUF/2). The floor doubles, from at least L, after a window in which
// most busy passes did not wait, and decays by 1/8 after any other. Lowering
// the limit cannot retract bytes already queued under the previous limit.
func (g *CarrierGate) Adjust(now time.Time, rate float64) {
	if g.raw == nil {
		return
	}
	if now.Sub(g.window) >= gateWindow {
		if g.passes > 0 && 2*g.waits < g.passes {
			g.floor = 2 * max(g.floor, float64(g.unsent))
		} else {
			g.floor *= 7.0 / 8
		}
		g.window, g.passes, g.waits = now, 0, 0
		g.sndbuf = sendBuffer(g.raw)
		// A writer-bound window must not leave an unreachable floor that
		// would take minutes to decay when the carrier becomes the bottleneck.
		g.floor = min(g.floor, float64(max(g.sndbuf/2, MinUnsent)))
	}
	g.unsent = min(max(int(max(UnsentTime.Seconds()*rate, g.floor)), MinUnsent), max(g.sndbuf/2, MinUnsent))
	// Only a change by a quarter is worth a system call.
	if 4*g.unsent < 3*g.lowat || 4*g.unsent > 5*g.lowat {
		if setUnsentLowat(g.raw, g.unsent) == nil {
			g.lowat = g.unsent
		}
	}
}

// Unit is the batch the writer takes after each Wait.
func (g *CarrierGate) Unit() int {
	if g.raw == nil {
		return MaxUnit
	}
	return g.lowat / 2
}
