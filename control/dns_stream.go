// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	dns "github.com/miekg/dns"
)

type dnsStreamWaiter struct {
	request  *dns.Msg
	response chan *plugin.DNSResponse
	complete <-chan struct{}
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

func newDNSStream(conn net.Conn, unsolicited func([]byte) error, onClose func()) *dnsStream {
	s := &dnsStream{conn: conn, pending: make(map[uint16][]*dnsStreamWaiter), done: make(chan struct{}), unsolicited: unsolicited, onClose: onClose}
	go s.read()
	return s
}

func frameID(wire []byte) uint16 {
	if len(wire) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(wire)
}

func (s *dnsStream) read() {
	defer func() {
		close(s.done)
		s.onClose()
	}()
	for {
		wire, err := readDNSFrame(s.conn)
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
			if waiter.complete != nil {
				<-waiter.complete
			}
		} else if err := s.unsolicited(wire); err != nil {
			s.err = err
			return
		}
	}
}

func (s *dnsStream) exchange(ctx context.Context, request *plugin.DNSExchange) (*plugin.DNSResponse, error) {
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
	waiter := &dnsStreamWaiter{request: message, response: make(chan *plugin.DNSResponse, 1)}
	if message != nil && len(message.Question) == 1 {
		qtype := message.Question[0].Qtype
		if qtype == dns.TypeAXFR || qtype == dns.TypeIXFR {
			waiter.complete = ctx.Done()
		}
	}
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
	err = writeDNSFrame(s.conn, wire)
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
