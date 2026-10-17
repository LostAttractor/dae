// SPDX-License-Identifier: AGPL-3.0-only

// Package dnscache provides bounded DNS response caching independently of
// upstream selection. It observes both relayed and plugin-local final responses.
package dnscache

import (
	"container/list"
	"context"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/plugin"
	dns "github.com/miekg/dns"
)

var Plugin = plugin.Definition{Configure: Configure}

type settings struct {
	Size        int
	MemoryLimit int
	FixedTTL    []string
}

type key struct{ context, network, query string }
type entry struct {
	key      key
	response *plugin.DNSResponse
	expires  time.Time
	bytes    int
}

type Cache struct {
	mu                        sync.Mutex
	entries                   map[key]*list.Element
	lru                       list.List
	limit, memoryLimit, bytes int
	fixed                     map[string]uint32
	hits, misses, bypasses    uint64
	expired, evicted          uint64
}

func Configure(spec plugin.Spec) (plugin.Factory, error) {
	conf, fixed, err := parseSettings(spec)
	if err != nil {
		return nil, err
	}
	return func(_ context.Context, services plugin.Services) (plugin.Plugin, error) {
		c := &Cache{entries: make(map[key]*list.Element), limit: conf.Size, memoryLimit: conf.MemoryLimit, fixed: fixed}
		if services.Metrics != nil {
			if err := services.Metrics.Register(c); err != nil {
				return nil, fmt.Errorf("cache metrics: %w", err)
			}
		}
		return c, nil
	}, nil
}

func parseSettings(spec plugin.Spec) (settings, map[string]uint32, error) {
	conf := settings{Size: 32768, MemoryLimit: 67108864}
	if err := plugin.DecodeSettingsFields(spec.Config, map[string]any{
		"size": &conf.Size, "memory_limit": &conf.MemoryLimit,
		"fixed_domain_ttl": &conf.FixedTTL,
	}); err != nil {
		return conf, nil, err
	}
	if conf.Size < 1 || conf.MemoryLimit < 65536 {
		return conf, nil, fmt.Errorf("size must be positive; memory_limit must be at least 65536")
	}
	fixed := make(map[string]uint32)
	for _, item := range conf.FixedTTL {
		name, value, ok := strings.Cut(string(item), ":")
		ttl, err := strconv.ParseUint(strings.TrimSpace(value), 0, 31)
		if !ok || err != nil {
			return conf, nil, fmt.Errorf("invalid value in fixed_domain_ttl; expected domain:ttl")
		}
		fixed[dns.CanonicalName(strings.TrimSpace(name))] = uint32(ttl)
	}
	return conf, fixed, nil
}

func (*Cache) Plan() plugin.Plan { return plugin.Plan{DNS: []plugin.DNSScope{{}}} }

func cacheKey(request *plugin.DNSExchange) (key, bool) {
	m := request.MessageCopy()
	if m == nil || m.Response || m.Opcode != dns.OpcodeQuery || len(m.Question) != 1 ||
		m.Question[0].Qclass != dns.ClassINET || len(m.Answer) != 0 || len(m.Ns) != 0 || m.Truncated || m.Rcode != 0 {
		return key{}, false
	}
	q := m.Question[0]
	if q.Qtype == dns.TypeAXFR || q.Qtype == dns.TypeIXFR || q.Qtype == dns.TypeTKEY {
		return key{}, false
	}
	for _, rr := range m.Extra {
		if _, ok := rr.(*dns.OPT); !ok {
			return key{}, false
		}
	}
	if !replayableExtra(m.Extra) {
		return key{}, false
	}
	canonical := m
	canonical.Id = 0
	canonical.Compress = false
	canonical.Question[0].Name = dns.CanonicalName(q.Name)
	wire, err := canonical.Pack()
	if err != nil || len(wire) > 4096 {
		return key{}, false
	}
	return key{request.ContextKey + "/" + request.Destination.String(), request.Network, string(wire)}, true
}

func replayableExtra(records []dns.RR) bool {
	optSeen := false
	for _, rr := range records {
		opt, ok := rr.(*dns.OPT)
		if !ok {
			// Ordinary additional records are safe; transaction signatures are not.
			if rr.Header().Rrtype == dns.TypeTSIG || rr.Header().Rrtype == dns.TypeSIG {
				return false
			}
			continue
		}
		if optSeen || opt.Version() != 0 {
			return false
		}
		optSeen = true
		for _, option := range opt.Option {
			switch option.(type) {
			case *dns.EDNS0_SUBNET, *dns.EDNS0_PADDING, *dns.EDNS0_NSID:
			default:
				return false
			}
		}
	}
	return true
}

func (c *Cache) WrapDNS(next plugin.DNSHandler) plugin.DNSHandler {
	return func(ctx context.Context, request *plugin.DNSExchange) (*plugin.DNSResponse, error) {
		k, ok := cacheKey(request)
		var query *dns.Msg
		if ok {
			query = request.MessageCopy()
			c.mu.Lock()
			if elem := c.entries[k]; elem != nil {
				e := elem.Value.(*entry)
				now := time.Now()
				if now.Before(e.expires) {
					c.lru.MoveToFront(elem)
					c.hits++
					response := e.response.Copy()
					elapsed := uint32(now.Sub(e.response.ReceivedAt) / time.Second)
					c.mu.Unlock()
					message := response.MessageCopy()
					for _, section := range [][]dns.RR{message.Answer, message.Ns, message.Extra} {
						for _, rr := range section {
							if rr.Header().Rrtype != dns.TypeOPT {
								rr.Header().Ttl -= min(rr.Header().Ttl, elapsed)
							}
						}
					}
					message.Id = query.Id
					message.Question = slices.Clone(query.Question)
					response.DNSPacket = plugin.DNSMessage(message)
					response.Cached = true
					return response, nil
				}
				c.remove(elem)
				c.expired++
			}
			c.misses++
			c.mu.Unlock()
		} else {
			c.mu.Lock()
			c.bypasses++
			c.mu.Unlock()
		}
		response, err := next(ctx, request)
		if err == nil && response != nil && !response.Cached && ok {
			if ttl, exists := c.fixed[dns.CanonicalName(query.Question[0].Name)]; exists {
				// Wire is authoritative. Never repair an opaque/malformed packet
				// by unpacking loosely and then discarding the original bytes.
				message := response.MessageCopy()
				if message != nil && netutils.ValidateDnsResponse(query, message, query.Id) == nil && !signed(message) {
					response = response.Copy()
					for _, rr := range message.Answer {
						rr.Header().Ttl = ttl
					}
					message.AuthenticatedData = false
					response.DNSPacket = plugin.DNSMessage(message)
				}
			}
		}
		return response, err
	}
}

func signed(m *dns.Msg) bool {
	for _, section := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			switch rr.Header().Rrtype {
			case dns.TypeRRSIG, dns.TypeTSIG, dns.TypeSIG:
				return true
			}
		}
	}
	return false
}

func (c *Cache) ObserveDNS(_ context.Context, request *plugin.DNSExchange, response *plugin.DNSResponse) {
	if response.Cached {
		return
	}
	k, ok := cacheKey(request)
	if !ok {
		return
	}
	m := response.MessageCopy()
	// Signed messages pass through unchanged, including authentication flags.
	// Retaining only unsigned responses avoids replaying transaction signatures.
	if m == nil || !m.Response || m.Truncated || signed(m) || !replayableExtra(m.Extra) ||
		(m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError) {
		return
	}
	query := request.MessageCopy()
	if ttl, exists := c.fixed[dns.CanonicalName(query.Question[0].Name)]; exists && ttl == 0 {
		return
	}
	ttl := ^uint32(0) // No ordinary RR has contributed a lifetime yet.
	negative := true
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == query.Question[0].Qtype || query.Question[0].Qtype == dns.TypeANY {
			negative = false
		}
	}
	negative = negative || m.Rcode == dns.RcodeNameError
	soa := false
	if negative {
		for _, rr := range m.Ns {
			if record, ok := rr.(*dns.SOA); ok {
				if record.Minttl >= 1<<31 {
					return
				}
				ttl = min(ttl, record.Minttl)
				soa = true
			}
		}
	}
	for _, section := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			// RFC 2181: a high-bit TTL means zero. Reject before storing
			// the original TTL, which aging could turn into a valid long TTL.
			if rr.Header().Ttl >= 1<<31 {
				return
			}
			ttl = min(ttl, rr.Header().Ttl)
		}
	}
	if ttl == ^uint32(0) || ttl == 0 || negative && !soa {
		return
	}
	at := response.ReceivedAt
	expires := at.Add(time.Duration(ttl) * time.Second)
	if !time.Now().Before(expires) {
		return
	}
	wire, err := m.Pack()
	if err != nil {
		return
	}
	bytes := 4*len(wire) + len(k.context) + len(k.query) + 256
	if bytes > c.memoryLimit {
		return
	}
	e := &entry{key: k, response: response.Copy(), expires: expires, bytes: bytes}
	if negative {
		// RFC 2308: clients must see the remaining negative lifetime too,
		// rather than starting a new MINIMUM interval on every cache hit.
		for _, rr := range m.Ns {
			if record, ok := rr.(*dns.SOA); ok {
				record.Hdr.Ttl = min(record.Hdr.Ttl, ttl)
			}
		}
	}
	e.response.DNSPacket = plugin.DNSMessage(m)
	c.mu.Lock()
	defer c.mu.Unlock()
	if old := c.entries[k]; old != nil {
		c.remove(old)
	}
	for len(c.entries) >= c.limit || c.bytes+bytes > c.memoryLimit {
		c.remove(c.lru.Back())
		c.evicted++
	}
	c.entries[k] = c.lru.PushFront(e)
	c.bytes += bytes
}

func (c *Cache) remove(elem *list.Element) {
	e := elem.Value.(*entry)
	delete(c.entries, e.key)
	c.bytes -= e.bytes
	c.lru.Remove(elem)
}

func (c *Cache) Run(ctx context.Context, _ *http.Client) error {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-ticker.C:
			c.expire(now)
		}
	}
}

func (c *Cache) expire(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, elem := range c.entries {
		if !now.Before(elem.Value.(*entry).expires) {
			c.remove(elem)
			c.expired++
		}
	}
}

func (c *Cache) Report() any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return map[string]any{"entries": len(c.entries), "limit": c.limit, "bytes": c.bytes, "memory_limit": c.memoryLimit, "hits": c.hits, "misses": c.misses}
}
