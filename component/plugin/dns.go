// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	dns "github.com/miekg/dns"
)

// DNSRequest and its wire/message are owned by one synchronous invocation.
// Copy before changing or retaining them. Wire is the exact client packet;
// a plugin changing Message must also replace Wire before calling next.
type DNSRequest struct {
	Message                                  *dns.Msg
	Wire                                     []byte
	Network                                  string
	Source, OriginalDestination, Destination netip.AddrPort
	Interface                                uint32
	// ServerAssigned prevents a later general resolver policy from overriding an
	// explicit per-domain assignment. Caches must isolate the selected Destination.
	ServerAssigned bool
	// Independent marks an auxiliary query with its own transport lifetime.
	// Cancelling it cannot close the client's shared TCP stream, and unsolicited
	// frames from it must not be delivered to the client.
	Independent bool
	// ContextKey isolates policy, source, destination, process and mark. Caches
	// must include it, the transport and all response-varying query fields.
	ContextKey string
	// Dial methods preserve the intercepted flow's identity while routing the
	// requested IP:port and optional trusted endpoint hostname (not the question
	// name). Hostname affects routing, while the selected IP remains the dial target.
	DialContext  func(ctx context.Context, network, address, hostname string) (net.Conn, error)
	ListenPacket func(ctx context.Context, address, hostname string) (net.PacketConn, error)
	Resolve      func(context.Context, *DNSRequest, []string) (*DNSResponse, error)
	// Client routes auxiliary HTTP requests with the same intercepted identity.
	// Its connection pools belong to this invocation; do not retain it afterwards.
	Client *http.Client
}

type DNSResponse struct {
	Message    *dns.Msg
	Wire       []byte
	ReceivedAt time.Time
	// Cached marks replayed responses. ReceivedAt remains the original receipt
	// time; successful client delivery independently refreshes registry retention.
	Cached bool
	Origin string
}

type DNSHandler func(context.Context, *DNSRequest) (*DNSResponse, error)

// DNSPlugin may answer locally or call next synchronously. Configuration order
// is request A -> B -> relay, response B -> A. Errors do not implicitly fall
// through to a different resolver. Unsupported requests should call next.
type DNSPlugin interface {
	Plugin
	WrapDNS(DNSHandler) DNSHandler
}

// DNSObserver sees final valid responses, including local and cached answers,
// after middleware and successful delivery. It cannot change the delivered response.
// ReceivedAt is nonzero: the core supplies delivery time if the producer omitted it.
// Calls may be concurrent; background consumers must copy retained data.
type DNSObserver interface {
	ObserveDNS(context.Context, *DNSRequest, *DNSResponse)
}

// DNSResolver is an optional cross-plugin service for explicit server
// assignments. It belongs to resolver plugins, never the transparent core.
type DNSResolver interface {
	ResolveDNS(context.Context, *DNSRequest, []string) (*DNSResponse, error)
}

// DNSAddressPolicy can preserve an already selected DNS IP when dialing an
// intercepted flow. It never captures traffic or invents a destination. The
// first applicable policy wins, including an applicable false decision.
type DNSAddressPolicy interface {
	UseDNSAddress(host string, proxy bool) (use, applicable bool)
}

// An empty name/type list matches everything; an empty Plan.DNS matches no
// requests. Names use the same whole-host * and ? globs as HTTP scopes.
type DNSScope struct {
	Names []string
	Types []uint16
}

func (s DNSScope) Match(m *dns.Msg) bool {
	if m == nil || m.Response || m.Opcode != dns.OpcodeQuery || len(m.Question) != 1 {
		return false
	}
	q := m.Question[0]
	matched := len(s.Types) == 0
	for _, t := range s.Types {
		matched = matched || t == q.Qtype
	}
	if !matched {
		return false
	}
	if len(s.Names) == 0 {
		return true
	}
	name := strings.TrimSuffix(q.Name, ".")
	for _, pattern := range s.Names {
		if (Scope{{Host: strings.TrimSuffix(pattern, ".")}}).Match(name, 53) {
			return true
		}
	}
	return false
}

func (r *DNSRequest) Copy() *DNSRequest {
	copy := *r
	copy.Wire = append([]byte(nil), r.Wire...)
	if r.Message != nil {
		copy.Message = r.Message.Copy()
	}
	return &copy
}

func (r *DNSResponse) Copy() *DNSResponse {
	copy := *r
	copy.Wire = append([]byte(nil), r.Wire...)
	if r.Message != nil {
		copy.Message = r.Message.Copy()
	}
	return &copy
}
