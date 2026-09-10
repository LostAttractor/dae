// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"math/bits"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/pkg/membuffer"
	"github.com/daeuniverse/outbound/pool"
	log "github.com/sirupsen/logrus"
)

// Shared by ingress tasks and both directions of every MITM QUIC bridge,
// including overlapping control planes during reload. Accounts for checked-out
// buffer capacity; idle sync.Pool storage and QUIC's own buffers are separate.
var udpPacketMemory = membuffer.NewBudget(8 << 20)

type udpPacket struct {
	data   []byte
	memory membuffer.Reservation
}

func copyUDPPacket(data []byte, budget *membuffer.Budget) (udpPacket, bool) {
	size := 0
	if len(data) > 0 {
		// Request a power of two explicitly so the reservation covers the
		// buffer's capacity, not merely the datagram length.
		size = 1 << bits.Len(uint(len(data)-1))
	}
	memory, err := budget.Reserve(int64(size))
	if err != nil {
		return udpPacket{}, false
	}
	owned := pool.GetBuffer(size)[:len(data)]
	copy(owned, data)
	return udpPacket{data: owned, memory: memory}, true
}

func (p *udpPacket) release() {
	pool.PutBuffer(p.data)
	p.data = nil
	p.memory.Close()
}

type udpPacketDrops struct {
	total   atomic.Uint64
	lastLog atomic.Int64
}

func (d *udpPacketDrops) report(reason string) {
	total := d.total.Add(1)
	now := time.Now().UnixNano()
	for {
		last := d.lastLog.Load()
		if last != 0 && now >= last && now-last < int64(time.Minute) {
			return
		}
		if d.lastLog.CompareAndSwap(last, now) {
			log.WithFields(log.Fields{"reason": reason, "dropped_total": total}).Warn("UDP capacity exhausted; dropping packet")
			return
		}
	}
}
