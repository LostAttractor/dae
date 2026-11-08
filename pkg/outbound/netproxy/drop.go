package netproxy

import (
	"iter"
	"slices"
	"sync/atomic"
	"time"

	quic "github.com/daeuniverse/quic-go"
	log "github.com/sirupsen/logrus"
)

// Directions of a dropped datagram, named as in the traffic metrics: upload
// travels from the LAN towards the internet.
const (
	DropUpload   = "upload"
	DropDownload = "download"
)

// Drop counts the UDP datagrams this process discarded in one direction for
// one reason, inside one outbound transport, or in dae's own UDP datapath and
// local sockets when transport is empty. Only the layer that discards a
// datagram counts it; callers told of a drop, as by ErrPacketDropped, do not
// count it again. A nil Drop counts nothing.
type Drop struct {
	transport, direction, reason string
	quiet                        bool
	total                        atomic.Uint64
	lastLog                      atomic.Int64
}

var drops []*Drop

// NewDrop registers the counter of a transport, direction and reason. It is
// called during package initialization, once for each triple.
func NewDrop(transport, direction, reason string) *Drop {
	if slices.ContainsFunc(drops, func(d *Drop) bool {
		return d.transport == transport && d.direction == direction && d.reason == reason
	}) {
		panic("netproxy: duplicate drop counter " + transport + "/" + direction + "/" + reason)
	}
	d := &Drop{transport: transport, direction: direction, reason: reason}
	drops = append(drops, d)
	return d
}

// NewQuietDrop registers a counter of drops that are part of normal
// operation, such as replies that arrive after a close: counted, not logged.
func NewQuietDrop(transport, direction, reason string) *Drop {
	d := NewDrop(transport, direction, reason)
	d.quiet = true
	return d
}

// Drops yields every registered counter.
func Drops() iter.Seq[*Drop] { return slices.Values(drops) }

func (d *Drop) Transport() string { return d.transport }
func (d *Drop) Direction() string { return d.direction }
func (d *Drop) Reason() string    { return d.reason }
func (d *Drop) Load() uint64      { return d.total.Load() }

// Add counts n dropped datagrams. Unless the counter is quiet, it logs at
// most once a minute.
func (d *Drop) Add(n uint64) {
	if d == nil {
		return
	}
	total := d.total.Add(n)
	if d.quiet {
		return
	}
	now := time.Now().UnixNano()
	for {
		last := d.lastLog.Load()
		if last != 0 && now >= last && now-last < int64(time.Minute) {
			return
		}
		if d.lastLog.CompareAndSwap(last, now) {
			fields := log.Fields{"direction": d.direction, "reason": d.reason, "dropped_total": total}
			if d.transport != "" {
				fields["transport"] = d.transport
			}
			// Off the caller, which may be a receive loop that must not block.
			go log.WithFields(fields).Warn("Dropping UDP packets")
			return
		}
	}
}

// DatagramDrops are the counters a datagram transport over a carrier keeps
// under its own label.
type DatagramDrops struct {
	// A shared carrier cannot accept another outgoing datagram.
	CarrierQueueFull *Drop
	// A received datagram finds the queue towards its reader, or the table
	// reassembling its fragments, full.
	ReceiveFull *Drop
	// A received datagram belongs to an association closed here.
	ClosedStream *Drop
	// A datagram exceeds what the transport can ever send.
	TooLarge *Drop
	// A datagram was still queued when its QUIC connection closed.
	carrierClosed *Drop
}

func NewDatagramDrops(transport string) *DatagramDrops {
	return &DatagramDrops{
		CarrierQueueFull: NewDrop(transport, DropUpload, "carrier_queue_full"),
		ReceiveFull:      NewDrop(transport, DropDownload, "transport_receive_full"),
		ClosedStream:     NewQuietDrop(transport, DropDownload, "closed_stream"),
		TooLarge:         NewDrop(transport, DropUpload, "too_large"),
		carrierClosed:    NewQuietDrop(transport, DropUpload, "carrier_closed"),
	}
}

// QUICDatagramDropped counts the DATAGRAM frames a QUIC connection discards.
// It is the quic.Config.DatagramDropped of the transport's connections.
func (d *DatagramDrops) QUICDatagramDropped(reason quic.DatagramDropReason, _ int) {
	switch reason {
	case quic.DatagramDropTooLarge:
		d.TooLarge.Add(1)
	case quic.DatagramDropReceiveQueueFull:
		d.ReceiveFull.Add(1)
	case quic.DatagramDropClosed:
		d.carrierClosed.Add(1)
	}
}
