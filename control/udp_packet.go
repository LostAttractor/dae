// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"math/bits"
	"time"

	"github.com/daeuniverse/dae/pkg/membuffer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
)

// Shared by ingress tasks, sniffing packets, both directions of every MITM
// QUIC bridge and pushed reply backlogs, including overlapping control planes
// during reload. Accounts for checked-out buffer capacity; idle sync.Pool
// storage and QUIC's own buffers are separate.
var udpPacketMemory = netproxy.DatagramMemory

type udpPacket struct {
	data     []byte
	deadline time.Time
	owned    bool
	memory   membuffer.Reservation
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
	return udpPacket{data: owned, owned: true, memory: memory}, true
}

// take moves the allocation and its reservation; borrowed data is copied once.
func (p *udpPacket) take(budget *membuffer.Budget) (udpPacket, bool) {
	packet := *p
	if !p.owned {
		var ok bool
		packet, ok = copyUDPPacket(p.data, budget)
		if !ok {
			return udpPacket{}, false
		}
		packet.deadline = p.deadline
	}
	*p = udpPacket{}
	return packet, true
}

func (p *udpPacket) release() {
	if p.owned {
		pool.PutBuffer(p.data)
	}
	p.memory.Close()
	*p = udpPacket{}
}

// UDP packets control drops itself, by direction and reason.
var (
	// The tproxy socket's receive queue overflowed.
	dropSocketOverflow = netproxy.NewDrop(netproxy.DropUpload, "socket_overflow")
	dropTruncated      = netproxy.NewDrop(netproxy.DropUpload, "truncated")
	// The packet has no route: its kernel routing record or the endpoint
	// it was queued for is gone.
	dropRouteMissing   = netproxy.NewQuietDrop(netproxy.DropUpload, "route_missing")
	dropSourceQueue    = netproxy.NewDrop(netproxy.DropUpload, "source_queue_full")
	dropTaskLimit      = netproxy.NewDrop(netproxy.DropUpload, "task_limit")
	dropSourceLimit    = netproxy.NewDrop(netproxy.DropUpload, "source_limit")
	dropUploadMemory   = netproxy.DropUploadMemory
	dropDownloadMemory = netproxy.DropDownloadMemory
	// The packet's deadline passed before it was sent.
	dropExpired       = netproxy.NewDrop(netproxy.DropUpload, "expired")
	dropSetupCapacity = netproxy.NewDrop(netproxy.DropUpload, "setup_capacity")
	// Opening the association failed; counts the datagrams its setup buffered.
	dropSetupFailed       = netproxy.NewDrop(netproxy.DropUpload, "setup_failed")
	dropSlowWriteCapacity = netproxy.NewDrop(netproxy.DropUpload, "slow_write_capacity")
	dropEndpointLimit     = netproxy.NewDrop(netproxy.DropUpload, "endpoint_limit")
	// The packet resource budget or the source's socket limit is full.
	dropResourceLimit = netproxy.NewDrop(netproxy.DropUpload, "packet_resource_limit")
	dropDNSAdmission  = netproxy.NewDrop(netproxy.DropUpload, "dns_admission")
	dropUploadMITM    = netproxy.NewDrop(netproxy.DropUpload, "mitm_bridge_full")
	dropDownloadMITM  = netproxy.NewDrop(netproxy.DropDownload, "mitm_bridge_full")
	// A request-routed MITM source sent to another destination, or a
	// destination socket received from another source.
	dropUploadFiltered   = netproxy.NewQuietDrop(netproxy.DropUpload, "filtered")
	dropDownloadFiltered = netproxy.NewQuietDrop(netproxy.DropDownload, "filtered")
	dropReplyQueue       = netproxy.NewDrop(netproxy.DropDownload, "reply_queue_full")
	// The client's reply socket had no room, or sending the reply failed.
	dropReplySocketFull = netproxy.NewDrop(netproxy.DropDownload, "reply_socket_full")
	dropReplySendFailed = netproxy.NewDrop(netproxy.DropDownload, "reply_send_failed")
)
