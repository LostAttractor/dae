// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	dns "github.com/miekg/dns"
)

// DNSRequest contains query data and routing identity, without runtime services.
// Replace DNSPacket to edit a query; its immutable representation can be shared.
type DNSRequest struct {
	DNSPacket
	Network                                  string
	Source, OriginalDestination, Destination netip.AddrPort
	SourceMAC                                [6]byte
	SourceOrigin                             SourceOrigin
	Interface                                uint32
	// ServerAssigned prevents a later general resolver policy from overriding an
	// explicit per-domain assignment. Caches must isolate the selected Destination.
	ServerAssigned bool
	// Chain identifies the host's ordered plugin instances. Caches of results
	// derived by plugins isolate it; raw upstream answers do not depend on it.
	Chain uint64
	// Egress identifies the network position an upstream answer stands for:
	// the selected node's physical path, the member paths of a group that picks
	// a node per connection, or direct traffic with its mark. Outbound groups
	// otherwise only choose an egress and never enter it. Empty is unknown. It
	// is set only at the upstream exchange boundary.
	Egress string
	// Upstream identifies the resolver that answers; see DNSUpstream.Endpoint.
	// It is set only at the upstream exchange boundary.
	Upstream string
}

// DNSUpstreamKey identifies a raw upstream answer by the resolver that answered
// and the egress it was reached through, independently of the resolved address
// or plain-DNS transport.
type DNSUpstreamKey struct {
	Egress   string
	Endpoint string
}

func (r DNSRequest) UpstreamKey() DNSUpstreamKey {
	return DNSUpstreamKey{Egress: r.Egress, Endpoint: r.Upstream}
}

// WithUpstream binds the request to one transport attempt. Execution and
// diagnostics share it so that both derive the same upstream identity.
func (r DNSRequest) WithUpstream(upstream DNSUpstream) DNSRequest {
	r.Network, r.Destination, r.Upstream = upstream.Network, upstream.Address, upstream.Endpoint
	if r.Upstream == "" {
		r.Upstream = PlainDNSEndpoint(upstream.Address.String())
	}
	return r
}

// PlainDNSEndpoint names a plain DNS resolver at host:port, which UDP and TCP
// share.
func PlainDNSEndpoint(hostport string) string {
	return "dns://" + hostport
}

// DNSExchange belongs to one synchronous invocation. Copy retains its scoped
// services; Fork additionally gives an auxiliary query an independent transport
// lifetime. Neither may outlive the invocation. Background work retains only data.
type DNSExchange struct {
	DNSRequest
	independent bool
	// Dial methods preserve the intercepted flow's identity while routing the
	// requested IP:port and optional trusted endpoint hostname (not the question
	// name). Hostname affects routing, while the selected IP remains the dial target.
	DialContext  func(ctx context.Context, network, address, hostname string) (net.Conn, error)
	ListenPacket func(ctx context.Context, address, hostname string) (net.PacketConn, error)
	Resolve      func(context.Context, *DNSExchange, []string) (*DNSResponse, error)
	// RouteUpstream routes the upstream and selects its node, sets Egress and
	// installs dial methods bound to that selection. Only
	// DNSUpstreamQuery.Prepare calls this hook.
	RouteUpstream func(context.Context, *DNSExchange, DNSUpstream) (*DNSExchange, error)
	// SelectCaches runs once per upstream query, on the actual query packet.
	SelectCaches func(DNSPacket) []DNSUpstreamCache
	// Client routes auxiliary HTTP requests with the same intercepted identity.
	// Its connection pools belong to this invocation; do not retain it afterwards.
	Client *http.Client
}

type DNSResponse struct {
	DNSPacket
	ReceivedAt time.Time
	// Cached marks replayed responses. ReceivedAt remains the original receipt
	// time; registering the answer before delivery refreshes registry retention.
	Cached bool
	Origin string
}

type DNSHandler func(context.Context, *DNSExchange) (*DNSResponse, error)

// DNSUpstream describes one concrete transport attempt. Endpoint names the
// resolver independently of the resolved address: plain DNS is dns://host:port
// for UDP and TCP alike, other protocols keep their URL including HTTP path and
// query. Empty means plain DNS at Address.
type DNSUpstream struct {
	Network  string
	Address  netip.AddrPort
	Hostname string
	Endpoint string
}

// DNSUpstreamQuery is one query's upstream cache decision across every
// candidate it may use: addresses, transports and fallbacks. Prepare each
// candidate through it, then call Finish once with the delivered result, so
// each consulted cache records at most one outcome for the upstream query.
type DNSUpstreamQuery struct {
	request *DNSExchange
	caches  []DNSUpstreamCache
	mu      sync.Mutex
	looked  bool
	hits    map[*DNSResponse]int // Replays by the index of the answering cache.
}

func (r *DNSExchange) UpstreamQuery() *DNSUpstreamQuery {
	query := &DNSUpstreamQuery{request: r}
	if r.SelectCaches != nil {
		query.caches = r.SelectCaches(r.DNSPacket)
	}
	return query
}

// Prepare selects the egress before exposing any cache or transport access.
// Reuse a prepared exchange within a synchronous decision; prepare again after
// network I/O, because routing and node selection may have changed meanwhile.
func (q *DNSUpstreamQuery) Prepare(ctx context.Context, upstream DNSUpstream) (*PreparedDNSExchange, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	request := q.request.Copy()
	if q.request.RouteUpstream != nil {
		var err error
		request, err = q.request.RouteUpstream(ctx, request, upstream)
		if err != nil {
			return nil, err
		}
	}
	request.DNSRequest = request.WithUpstream(upstream)
	return &PreparedDNSExchange{query: q, request: request}, nil
}

// Finish records the query's outcome in each consulted cache. A replay counts
// as a hit in its cache and a miss in caches consulted before it; any other
// result, including failure, is a miss. Queries no cache saw are not counted.
func (q *DNSUpstreamQuery) Finish(response *DNSResponse) {
	q.mu.Lock()
	looked := q.looked
	index, hit := q.hits[response]
	q.mu.Unlock()
	if !looked {
		return
	}
	for i, cache := range q.caches {
		if hit && i > index {
			break
		}
		cache.RecordDNSUpstream(q.request, hit && i == index)
	}
}

// PreparedDNSExchange owns one egress selection for one upstream candidate.
type PreparedDNSExchange struct {
	query   *DNSUpstreamQuery
	request *DNSExchange
}

// Lookup replays a cached answer for this candidate's egress and resolver
// without a network attempt; Finish records the outcome.
func (p *PreparedDNSExchange) Lookup() *DNSResponse {
	q := p.query
	q.mu.Lock()
	q.looked = true
	q.mu.Unlock()
	for i, cache := range q.caches {
		if response := cache.LookupDNSUpstream(p.request); response != nil {
			q.mu.Lock()
			if q.hits == nil {
				q.hits = make(map[*DNSResponse]int)
			}
			q.hits[response] = i
			q.mu.Unlock()
			return response
		}
	}
	return nil
}

// Exchange replays a cached answer for this candidate, or runs the network
// attempt and offers its raw answer to the caches.
func (p *PreparedDNSExchange) Exchange(ctx context.Context, transport DNSHandler) (*DNSResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if response := p.Lookup(); response != nil {
		return response, nil
	}
	response, err := transport(ctx, p.request)
	if err != nil || response == nil || response.Cached || ctx.Err() != nil {
		return response, err
	}
	// Inner caches store first, so an outer cache retains their TTL policy.
	for i := len(p.query.caches) - 1; i >= 0; i-- {
		response = p.query.caches[i].StoreDNSUpstream(p.request, response)
	}
	return response, nil
}

// ExchangeUpstream is called after request policy and before response policy,
// for a query with a single upstream candidate.
func (r *DNSExchange) ExchangeUpstream(ctx context.Context, upstream DNSUpstream, transport DNSHandler) (*DNSResponse, error) {
	query := r.UpstreamQuery()
	prepared, err := query.Prepare(ctx, upstream)
	if err != nil {
		return nil, err
	}
	response, err := prepared.Exchange(ctx, transport)
	query.Finish(response)
	return response, err
}

// DNSUpstreamCache caches only raw transport answers, outside response policy.
// It counts lookups per upstream query, not per candidate or attempt.
type DNSUpstreamCache interface {
	Plugin
	// LookupDNSUpstream replays a cached answer without recording an outcome.
	LookupDNSUpstream(*DNSExchange) *DNSResponse
	// RecordDNSUpstream records one query's outcome: whether this cache answered.
	RecordDNSUpstream(request *DNSExchange, hit bool)
	// StoreDNSUpstream retains a raw answer and returns the answer to deliver,
	// which may carry cache-owned TTL policy.
	StoreDNSUpstream(*DNSExchange, *DNSResponse) *DNSResponse
}

// DNSPlugin may answer locally or call next synchronously. Configuration order
// is request A -> B -> relay, response B -> A. Errors do not implicitly fall
// through to a different resolver. Unsupported requests should call next.
type DNSPlugin interface {
	Plugin
	WrapDNS(DNSHandler) DNSHandler
}

// DNSObserver sees final valid responses, including local and cached answers,
// after middleware and successful delivery. It cannot change the delivered response.
// ReceivedAt is nonzero: the core supplies the time it registered the answer,
// just before delivery, if the producer omitted it.
// Calls may be concurrent; background consumers must copy retained data.
type DNSObserver interface {
	ObserveDNS(context.Context, *DNSExchange, *DNSResponse)
}

// DNSResolver is an optional cross-plugin service for explicit server
// assignments. It belongs to resolver plugins, never the transparent core.
type DNSResolver interface {
	ResolveDNS(context.Context, *DNSExchange, []string) (*DNSResponse, error)
}

// DNSAddressPolicy decides whether a proxied intercepted flow dials its DNS
// address instead of sending the sniffed name. Direct flows always dial the
// client's address. It never captures traffic or invents a destination. The
// first applicable policy wins, including an applicable false decision.
type DNSAddressPolicy interface {
	UseDNSAddress(host string) (use, applicable bool)
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
	return s.matchQuestion(m.Question[0])
}

func (s DNSScope) MatchPacket(packet DNSPacket) bool {
	header, valid := packet.Header()
	q, single := packet.Question()
	return valid && !header.Response && header.Opcode == dns.OpcodeQuery && single && s.matchQuestion(q)
}

func (s DNSScope) matchQuestion(q dns.Question) bool {
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

func (r *DNSExchange) Copy() *DNSExchange {
	return new(*r)
}

func (r *DNSExchange) Fork() *DNSExchange {
	copy := r.Copy()
	copy.independent = true
	return copy
}

func (r *DNSExchange) Independent() bool { return r.independent }

func (r *DNSResponse) Copy() *DNSResponse {
	return new(*r)
}
