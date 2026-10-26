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
// one reason. Only the layer that discards a datagram counts it; callers
// told of a drop, as by ErrPacketDropped, do not count it again.
type Drop struct {
	direction, reason string
	quiet             bool
	total             atomic.Uint64
	lastLog           atomic.Int64
}

var drops []*Drop

// NewDrop registers the counter of a direction and reason. It is called
// during package initialization, once for each pair.
func NewDrop(direction, reason string) *Drop {
	if slices.ContainsFunc(drops, func(d *Drop) bool { return d.direction == direction && d.reason == reason }) {
		panic("netproxy: duplicate drop counter " + direction + "/" + reason)
	}
	d := &Drop{direction: direction, reason: reason}
	drops = append(drops, d)
	return d
}

// NewQuietDrop registers a counter of drops that are part of normal
// operation, such as replies that arrive after a close: counted, not logged.
func NewQuietDrop(direction, reason string) *Drop {
	d := NewDrop(direction, reason)
	d.quiet = true
	return d
}

// Drops yields every registered counter.
func Drops() iter.Seq[*Drop] { return slices.Values(drops) }

func (d *Drop) Direction() string { return d.direction }
func (d *Drop) Reason() string    { return d.reason }
func (d *Drop) Load() uint64      { return d.total.Load() }

// Add counts n dropped datagrams. Unless the counter is quiet, it logs at
// most once a minute.
func (d *Drop) Add(n uint64) {
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
			// Off the caller, which may be a receive loop that must not block.
			go log.WithFields(log.Fields{"direction": d.direction, "reason": d.reason, "dropped_total": total}).Warn("Dropping UDP packets")
			return
		}
	}
}

// Drops shared by transports.
var (
	// A shared carrier cannot accept another outgoing datagram.
	DropCarrierQueueFull = NewDrop(DropUpload, "carrier_queue_full")
	// A received datagram finds the queue towards its reader, or the table
	// reassembling its fragments, full.
	DropReceiveFull = NewDrop(DropDownload, "transport_receive_full")
	// A received datagram belongs to an association closed here.
	DropClosedStream = NewQuietDrop(DropDownload, "closed_stream")
	// A queued datagram exceeds what the transport can ever send.
	dropTooLarge = NewDrop(DropUpload, "too_large")
)

func init() {
	quic.DatagramDropped = func(sending bool) {
		if sending {
			dropTooLarge.Add(1)
		} else {
			DropReceiveFull.Add(1)
		}
	}
}
