// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"bytes"
	"errors"

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
