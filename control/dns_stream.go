// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/plugin"
	dns "github.com/miekg/dns"
)

type dnsStreamWaiter struct {
	request  *dns.Msg
	response chan *plugin.DNSResponse
	transfer *dnsTCPDelivery
}

// A transfer's first response goes through middleware and downstream delivery.
// The transport context may end before either has finished.
type dnsTCPDelivery struct {
	done     chan struct{}
	wire     []byte
	unpooled sync.WaitGroup
}

type dnsTransferBoundary struct {
	serial      uint32
	currentSOAs int
	incremental bool
}

func (b *dnsTransferBoundary) finished(query, response *dns.Msg) bool {
	if query == nil || len(query.Question) != 1 || response == nil || !response.Response ||
		response.Id != query.Id || response.Opcode != query.Opcode {
		return false
	}
	if response.Rcode != dns.RcodeSuccess {
		return true
	}
	q := query.Question[0]
	zoneSOA := func(rr dns.RR) (*dns.SOA, bool) {
		soa, ok := rr.(*dns.SOA)
		return soa, ok && soa.Hdr.Class == q.Qclass && strings.EqualFold(soa.Hdr.Name, q.Name)
	}
	if b.currentSOAs == 0 {
		if len(response.Answer) == 0 {
			return false
		}
		opening, ok := zoneSOA(response.Answer[0])
		if !ok {
			return false
		}
		b.serial = opening.Serial
		if q.Qtype == dns.TypeIXFR && len(response.Answer) == 1 && len(query.Ns) == 1 {
			if client, ok := zoneSOA(query.Ns[0]); ok {
				// Serial numbers wrap; a one-SOA response is final only if the client is not older.
				if delta := b.serial - client.Serial; delta == 0 || delta > 1<<31 {
					return true
				}
			}
		}
	}
	for i, rr := range response.Answer {
		soa, ok := zoneSOA(rr)
		if !ok {
			continue
		}
		if soa.Serial != b.serial {
			b.incremental = b.incremental || q.Qtype == dns.TypeIXFR
			continue
		}
		b.currentSOAs++
		// IXFR deltas include the current SOA as well as the enclosing pair.
		if i == len(response.Answer)-1 && (b.currentSOAs == 2 && !b.incremental || b.currentSOAs == 3 && b.incremental) {
			return true
		}
	}
	return false
}

// dnsStream preserves a client's IDs and connection. It only correlates frames;
// it never coalesces queries, retries them, or opens a different transport.
type dnsStream struct {
	conn        net.Conn
	writeMu     sync.Mutex
	mu          sync.Mutex
	pending     map[uint16][]*dnsStreamWaiter
	done        chan struct{}
	err         error
	unsolicited func([]byte) error
	onClose     func()
}

func newDNSStream(conn net.Conn, idle time.Duration, unsolicited func([]byte) error, onClose func()) *dnsStream {
	s := &dnsStream{conn: conn, pending: make(map[uint16][]*dnsStreamWaiter), done: make(chan struct{}), unsolicited: unsolicited, onClose: onClose}
	go s.read(idle)
	return s
}

func frameID(wire []byte) uint16 {
	if len(wire) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(wire)
}

func (s *dnsStream) read(idle time.Duration) {
	defer func() {
		close(s.done)
		s.onClose()
	}()
	var transferQuery *dns.Msg
	var boundary dnsTransferBoundary
	for {
		if idle > 0 {
			_ = s.conn.SetReadDeadline(time.Now().Add(idle))
		}
		wire, err := netutils.ReadDNSFrame(s.conn)
		if err != nil {
			s.err = err
			return
		}
		id := frameID(wire)
		packet := plugin.DNSWire(wire)
		message := packet.MessageCopy()
		valid := message != nil
		s.mu.Lock()
		var waiter *dnsStreamWaiter
		for i, pending := range s.pending[id] {
			// A header-only error can complete a unique request without becoming
			// observable DNS evidence. Repeated IDs remain ambiguous without a
			// question, so leave those packets transparent and unassociated.
			emptyError := valid && len(s.pending[id]) == 1 && message.Response &&
				message.Rcode != dns.RcodeSuccess && len(message.Question) == 0 &&
				pending.request != nil && message.Opcode == pending.request.Opcode
			if !valid || pending.request == nil || emptyError || dnsResponseMatches(pending.request, message) {
				waiter = pending
				s.pending[id] = append(s.pending[id][:i], s.pending[id][i+1:]...)
				if len(s.pending[id]) == 0 {
					delete(s.pending, id)
				}
				break
			}
		}
		s.mu.Unlock()
		if waiter != nil {
			waiter.response <- &plugin.DNSResponse{DNSPacket: packet, ReceivedAt: time.Now(), Origin: "relay"}
			// Transfers may produce additional frames with the same ID. Their
			// first frame must reach the client before unsolicited continuation.
			if d := waiter.transfer; d != nil {
				<-d.done
				if d.wire == nil || !bytes.Equal(wire, d.wire) {
					s.err = errors.New("first DNS transfer response was not delivered unchanged")
					return
				}
				transferQuery = waiter.request
			}
		} else if err := s.unsolicited(wire); err != nil {
			s.err = err
			return
		}
		if transferQuery != nil && boundary.finished(transferQuery, message) {
			s.err = io.EOF
			return
		}
	}
}

func (s *dnsStream) exchange(ctx context.Context, request *plugin.DNSExchange, transfer *dnsTCPDelivery) (*plugin.DNSResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-s.done:
		return nil, s.err
	default:
	}
	wire, err := request.Wire()
	if err != nil {
		return nil, err
	}
	id := frameID(wire)
	message := request.MessageCopy()
	if message != nil && message.Response {
		message = nil // A client-supplied response remains an opaque frame.
	}
	waiter := &dnsStreamWaiter{request: message, response: make(chan *plugin.DNSResponse, 1), transfer: transfer}
	// Admission and write share ordering, including repeated IDs/questions.
	s.writeMu.Lock()
	// Cancelling one request retires the shared connection: keeping a partial
	// frame alive would corrupt all subsequent exchanges on this stream.
	stop := context.AfterFunc(ctx, func() { _ = s.conn.Close() })
	defer stop()
	if err := ctx.Err(); err != nil {
		s.writeMu.Unlock()
		return nil, err
	}
	s.mu.Lock()
	s.pending[id] = append(s.pending[id], waiter)
	s.mu.Unlock()
	err = netutils.WriteDNSFrame(s.conn, wire)
	s.writeMu.Unlock()
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		for i, w := range s.pending[id] {
			if w == waiter {
				s.pending[id] = append(s.pending[id][:i], s.pending[id][i+1:]...)
				if len(s.pending[id]) == 0 {
					delete(s.pending, id)
				}
				break
			}
		}
	}()
	if err != nil {
		return nil, err
	}
	select {
	case response := <-waiter.response:
		return response, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.done:
		select {
		case response := <-waiter.response:
			return response, nil
		default:
			return nil, s.err
		}
	}
}

func (s *dnsStream) close() { _ = s.conn.Close(); <-s.done }
