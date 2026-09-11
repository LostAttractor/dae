// SPDX-License-Identifier: AGPL-3.0-only

// Package dnscache provides bounded DNS response caching independently of
// upstream selection. It observes both relayed and plugin-local final responses.
package dnscache

import (
	"container/list"
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/config"
	dns "github.com/miekg/dns"
)

var Plugin = plugin.Definition{Setup: Setup, Validate: Validate}

type settings struct {
	Size        int                    `mapstructure:"size" default:"32768"`
	MemoryLimit int                    `mapstructure:"memory_limit" default:"67108864"`
	FixedTTL    []config.KeyableString `mapstructure:"fixed_domain_ttl"`
}

type key struct{ context, network, query string }
type entry struct {
	key         key
	response    *plugin.DNSResponse
	at, expires time.Time
	bytes       int
}

type Cache struct {
	mu                        sync.Mutex
	entries                   map[key]*list.Element
	lru                       list.List
	limit, memoryLimit, bytes int
	fixed                     map[string]uint32
	hits, misses              uint64
}

func Setup(_ context.Context, spec plugin.Spec, _ plugin.Services) (plugin.Plugin, error) {
	conf, fixed, err := parseSettings(spec)
	if err != nil {
		return nil, err
	}
	return &Cache{entries: make(map[key]*list.Element), limit: conf.Size, memoryLimit: conf.MemoryLimit, fixed: fixed}, nil
}

func Validate(spec plugin.Spec) error {
	_, _, err := parseSettings(spec)
	return err
}

func parseSettings(spec plugin.Spec) (settings, map[string]uint32, error) {
	var conf settings
	if err := config.SectionParser(reflect.ValueOf(&conf), spec.Config); err != nil {
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
			return conf, nil, fmt.Errorf("invalid fixed_domain_ttl %q", item)
		}
		fixed[dns.CanonicalName(strings.TrimSpace(name))] = uint32(ttl)
	}
	return conf, fixed, nil
}

func (*Cache) Plan() plugin.Plan { return plugin.Plan{DNS: []plugin.DNSScope{{}}} }

func cacheKey(request *plugin.DNSRequest) (key, bool) {
	m := request.Message
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
	canonical := m.Copy()
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
	return func(ctx context.Context, request *plugin.DNSRequest) (*plugin.DNSResponse, error) {
		k, ok := cacheKey(request)
		if ok {
			c.mu.Lock()
			if elem := c.entries[k]; elem != nil {
				e := elem.Value.(*entry)
				now := time.Now()
				if now.Before(e.expires) {
					c.lru.MoveToFront(elem)
					c.hits++
					response := e.response.Copy()
					elapsed := uint32(now.Sub(e.at) / time.Second)
					c.mu.Unlock()
					for _, section := range [][]dns.RR{response.Message.Answer, response.Message.Ns, response.Message.Extra} {
						for _, rr := range section {
							if rr.Header().Rrtype != dns.TypeOPT {
								rr.Header().Ttl -= min(rr.Header().Ttl, elapsed)
							}
						}
					}
					response.Message.Id = request.Message.Id
					response.Message.Question = append([]dns.Question(nil), request.Message.Question...)
					response.Wire = nil
					response.Cached = true
					return response, nil
				}
				c.remove(elem)
			}
			c.misses++
			c.mu.Unlock()
		}
		response, err := next(ctx, request)
		if err == nil && response != nil && !response.Cached && ok {
			if ttl, exists := c.fixed[dns.CanonicalName(request.Message.Question[0].Name)]; exists {
				// Wire is authoritative. Never repair an opaque/malformed packet
				// by unpacking loosely and then discarding the original bytes.
				message := response.Message
				if len(response.Wire) != 0 {
					message = new(dns.Msg)
					if netutils.UnpackDnsMessage(response.Wire, message) != nil {
						return response, nil
					}
				}
				if message != nil && netutils.ValidateDnsResponse(request.Message, message, request.Message.Id) == nil && !signed(message) {
					response = response.Copy()
					response.Message = message.Copy()
					response.Wire = nil
					for _, rr := range response.Message.Answer {
						rr.Header().Ttl = ttl
					}
					response.Message.AuthenticatedData = false
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

func (c *Cache) ObserveDNS(_ context.Context, request *plugin.DNSRequest, response *plugin.DNSResponse) {
	k, ok := cacheKey(request)
	m := response.Message
	// Signed messages pass through unchanged, including authentication flags.
	// Retaining only unsigned responses avoids replaying transaction signatures.
	if !ok || response.Cached || m == nil || !m.Response || m.Truncated || signed(m) || !replayableExtra(m.Extra) ||
		(m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError) {
		return
	}
	if ttl, exists := c.fixed[dns.CanonicalName(request.Message.Question[0].Name)]; exists && ttl == 0 {
		return
	}
	ttl := uint32(1<<31 - 1)
	count := 0
	negative := true
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == request.Message.Question[0].Qtype || request.Message.Question[0].Qtype == dns.TypeANY {
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
			count++
		}
	}
	if count == 0 || ttl == 0 || negative && !soa {
		return
	}
	at := response.ReceivedAt
	if at.IsZero() {
		at = time.Now()
	}
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
	e := &entry{key: k, response: response.Copy(), at: at, expires: expires, bytes: bytes}
	e.response.Wire = nil
	if negative {
		// RFC 2308: clients must see the remaining negative lifetime too,
		// rather than starting a new MINIMUM interval on every cache hit.
		for _, rr := range e.response.Message.Ns {
			if record, ok := rr.(*dns.SOA); ok {
				record.Hdr.Ttl = min(record.Hdr.Ttl, ttl)
			}
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if old := c.entries[k]; old != nil {
		c.remove(old)
	}
	for len(c.entries) >= c.limit || c.bytes+bytes > c.memoryLimit {
		c.remove(c.lru.Back())
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
			c.mu.Lock()
			for _, elem := range c.entries {
				if !now.Before(elem.Value.(*entry).expires) {
					c.remove(elem)
				}
			}
			c.mu.Unlock()
		}
	}
}

func (c *Cache) Report() any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return map[string]any{"entries": len(c.entries), "limit": c.limit, "bytes": c.bytes, "memory_limit": c.memoryLimit, "hits": c.hits, "misses": c.misses}
}
