// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"bytes"
	"errors"
	"slices"

	"github.com/daeuniverse/dae/common/netutils"
	dns "github.com/miekg/dns"
)

// DNSPacket is immutable. It is either an exact received packet or a locally
// constructed message. Copies share storage; editing requires replacement with
// DNSMessage. This keeps parsed data and serialized bytes consistent.
type DNSPacket struct {
	wire    []byte
	message *dns.Msg
}

// DNSWire copies the exact packet. Malformed/opaque packets remain forwardable
// but have no parsed message and cannot drive plugin policy or DNS observation.
func DNSWire(wire []byte) DNSPacket {
	p := DNSPacket{wire: bytes.Clone(wire)}
	if p.wire == nil {
		p.wire = []byte{}
	}
	message := new(dns.Msg)
	if netutils.UnpackDnsMessage(p.wire, message) == nil {
		p.message = message
	}
	return p
}

// DNSMessage copies a local message. The transport may truncate a local UDP
// response before encoding; exact received packets are never repacked implicitly.
func DNSMessage(message *dns.Msg) DNSPacket {
	if message == nil {
		return DNSPacket{}
	}
	return DNSPacket{message: message.Copy()}
}

// MessageCopy returns an owned, editable message, or nil for an opaque packet.
func (p DNSPacket) MessageCopy() *dns.Msg {
	if p.message == nil {
		return nil
	}
	return p.message.Copy()
}

// Header and Question return scalar copies without cloning resource records.
// Question succeeds only for a parsed packet containing exactly one question.
func (p DNSPacket) Header() (dns.MsgHdr, bool) {
	if p.message == nil {
		return dns.MsgHdr{}, false
	}
	return p.message.MsgHdr, true
}

func (p DNSPacket) Question() (dns.Question, bool) {
	if p.message == nil || len(p.message.Question) != 1 {
		return dns.Question{}, false
	}
	return p.message.Question[0], true
}

func (p DNSPacket) HasAdditional(types ...uint16) bool {
	if p.message == nil {
		return false
	}
	for _, record := range p.message.Extra {
		if slices.Contains(types, record.Header().Rrtype) {
			return true
		}
	}
	return false
}

// Replayable reports whether a parsed query can be independently reissued.
// Transfers, key negotiation and signed transactions must retain their original
// exchange. Caches and host policies may impose additional class/EDNS limits.
func (p DNSPacket) Replayable() bool {
	header, parsed := p.Header()
	question, single := p.Question()
	if !parsed || !single || header.Response || header.Opcode != dns.OpcodeQuery || p.HasAdditional(dns.TypeTSIG, dns.TypeSIG) {
		return false
	}
	return question.Qtype != dns.TypeAXFR && question.Qtype != dns.TypeIXFR && question.Qtype != dns.TypeTKEY
}

// ValidateResponse reads the immutable packets without allocating message copies.
func (p DNSPacket) ValidateResponse(response DNSPacket, allowEmptyQuestion bool) error {
	if p.message == nil || response.message == nil {
		return errors.New("empty or opaque DNS packet")
	}
	if allowEmptyQuestion {
		// The transport helper fills absent questions on negative replies.
		// Give it a scalar copy so immutable packet storage stays untouched.
		message := *response.message
		return netutils.ValidateDnsResponseAllowEmptyQuestion(p.message, &message, p.message.Id)
	}
	return netutils.ValidateDnsResponse(p.message, response.message, p.message.Id)
}

// IsWire distinguishes exact received bytes from a locally constructed message.
func (p DNSPacket) IsWire() bool { return p.wire != nil }

// Wire returns read-only bytes valid for the packet lifetime. Encoding errors
// from local messages are returned to the caller rather than silently dropped.
func (p DNSPacket) Wire() ([]byte, error) {
	if p.IsWire() {
		return p.wire, nil
	}
	if p.message == nil {
		return nil, errors.New("empty DNS packet")
	}
	// Pack updates EDNS extended RCODE fields, so it needs its own message.
	return p.message.Copy().Pack()
}
