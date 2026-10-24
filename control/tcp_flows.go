// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/internal/routingabi"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// tcpFlowCloseGrace is TCP_TIMEWAIT_LEN. A closed accepted socket finishes its
// closing handshake within it: the client's last segments, such as a
// retransmitted FIN or the ACK of dae's FIN, still reach dae and not the
// origin. A client that has not closed its side is reset by then (see
// tproxyListenConfig), so it sends nothing later.
const tcpFlowCloseGrace = 60 * time.Second

// tcpFlows ends the kernel flow state of accepted connections, which the
// kernel never deletes itself unless the client resets. Leases count the
// accepted connections of a tuple, so a finished connection never deletes
// the state of a newer one that reuses its tuple.
type tcpFlows struct {
	mu       sync.Mutex
	flows    *ebpf.Map // tcp_flow_map
	handoffs *ebpf.Map // routing_tuples_map
	grace    time.Duration
	leases   map[bpfTuplesKey]*tcpFlowLease
	closed   bool
}

type tcpFlowLease struct {
	live  int
	timer *time.Timer
	seq   uint64
}

func acceptedTuple(conn net.Conn) bpfTuplesKey {
	return tuplesKey(conn.RemoteAddr().(*net.TCPAddr).AddrPort(), conn.LocalAddr().(*net.TCPAddr).AddrPort(), unix.IPPROTO_TCP)
}

func (f *tcpFlows) accept(key bpfTuplesKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.flows == nil {
		return
	}
	if f.leases == nil {
		f.leases = make(map[bpfTuplesKey]*tcpFlowLease)
	}
	lease := f.leases[key]
	if lease == nil {
		lease = new(tcpFlowLease)
		f.leases[key] = lease
	}
	lease.live++
	if lease.timer != nil {
		lease.timer.Stop()
		lease.timer = nil
	}
}

// release deletes the flow state a grace period after the tuple's last
// accepted connection has finished.
func (f *tcpFlows) release(key bpfTuplesKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	lease := f.leases[key]
	if f.closed || lease == nil {
		return
	}
	if lease.live--; lease.live > 0 {
		return
	}
	lease.seq++
	seq := lease.seq
	lease.timer = time.AfterFunc(f.grace, func() { f.expire(key, lease, seq) })
}

func (f *tcpFlows) expire(key bpfTuplesKey, lease *tcpFlowLease, seq uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.leases[key] != lease || lease.live > 0 || lease.seq != seq {
		return
	}
	delete(f.leases, key)
	// A new SYN of the tuple has replaced the state and awaits its accept, or
	// the kernel forwards the tuple's new connection itself.
	var handoff bpfRoutingHandoff
	if err := f.handoffs.Lookup(&key, &handoff); err == nil {
		if live, err := handoffLive(&handoff); err != nil || live {
			return
		}
	}
	var flow bpfTcpFlowState
	if err := f.flows.Lookup(&key, &flow); err != nil || flow.Owner != routingabi.FALLBACK_TOKEN_RESERVED {
		return
	}
	if err := f.flows.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		log.WithError(err).Warn("Delete TCP flow state")
	}
}

// close leaves the pending states pinned. After a restart they still send the
// clients' late segments to dae, which resets them, instead of to the origin.
func (f *tcpFlows) close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	for _, lease := range f.leases {
		if lease.timer != nil {
			lease.timer.Stop()
		}
	}
	f.leases = nil
}
