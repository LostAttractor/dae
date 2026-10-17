// SPDX-License-Identifier: AGPL-3.0-only

// Package dnsrouter implements request/response DNS routing and upstream
// transports as an optional dae plugin. Responses are never cached here.
package dnsrouter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/network"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/proxylink"
	policy "github.com/daeuniverse/dae/plugins/dns-router/policy"
	"github.com/daeuniverse/dae/plugins/dns-router/transport"
	dns "github.com/miekg/dns"
)

var Plugin = plugin.Definition{Configure: Configure}

type Router struct {
	policy        *policy.Dns
	prefer        uint16
	interfaces    *network.InterfaceManager
	metrics       *routerMetrics
	upstreamNames []string
}

func parseSettings(spec plugin.Spec) (policy.Config, uint16, error) {
	conf := policy.Config{}
	var upstreams []string
	if err := plugin.DecodeSettingsFields(spec.Config, map[string]any{
		"ipversion_prefer": &conf.IPVersionPrefer,
		"upstream":         &upstreams,
		"routing": func(section *config_parser.Section) error {
			return plugin.DecodeSettingsFields(section, map[string]any{
				"request": func(section *config_parser.Section) error {
					return decodeRoutingSettings(section, &conf.Routing.Request.Rules, &conf.Routing.Request.Fallback)
				},
				"response": func(section *config_parser.Section) error {
					return decodeRoutingSettings(section, &conf.Routing.Response.Rules, &conf.Routing.Response.Fallback)
				},
			})
		},
	}); err != nil {
		return conf, 0, err
	}
	for _, value := range upstreams {
		conf.Upstream = append(conf.Upstream, config.KeyableString(value))
	}
	if conf.Routing.Request.Fallback == nil {
		conf.Routing.Request.Fallback = "asis"
	}
	if conf.Routing.Response.Fallback == nil {
		conf.Routing.Response.Fallback = "accept"
	}
	var prefer uint16
	switch conf.IPVersionPrefer {
	case 0:
	case 4:
		prefer = dns.TypeA
	case 6:
		prefer = dns.TypeAAAA
	default:
		return conf, 0, errors.New("ipversion_prefer must be 0, 4 or 6")
	}
	for _, upstream := range conf.Upstream {
		name, link := proxylink.SplitTag(string(upstream))
		if name == "" {
			return conf, 0, errors.New("DNS upstream requires a tag")
		}
		raw, err := url.Parse(link)
		if err != nil {
			return conf, 0, fmt.Errorf("upstream %q: invalid URL", name)
		}
		if _, _, _, _, err := policy.ParseRawUpstream(raw); err != nil {
			return conf, 0, fmt.Errorf("upstream %q: invalid transport, host or port", name)
		}
	}
	return conf, prefer, policy.Validate(&conf)
}

func decodeRoutingSettings(section *config_parser.Section, rules *[]*config_parser.RoutingRule, fallback *config.FunctionOrString) error {
	return plugin.DecodeSettingsFields(section, map[string]any{
		"_": rules,
		"fallback": func(param *config_parser.Param) error {
			switch {
			case param.AndFunctions != nil:
				*fallback = param.AndFunctions
			case param.Quoted:
				*fallback = config.QuotedString(param.Val)
			default:
				*fallback = param.Val
			}
			return nil
		},
	})
}

func Configure(spec plugin.Spec) (plugin.Factory, error) {
	conf, prefer, err := parseSettings(spec)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, services plugin.Services) (plugin.Plugin, error) {
		return prepare(ctx, conf, prefer, services)
	}, nil
}

func prepare(ctx context.Context, conf policy.Config, prefer uint16, services plugin.Services) (plugin.Plugin, error) {
	reader := routing.NewDatReaderOptimizer(ctx, assets.NewLocationFinder([]string{services.BaseDir}))
	request, err := routing.ApplyRulesOptimizers(conf.Routing.Request.Rules, &routing.AliasOptimizer{}, reader, &routing.MergeAndSortRulesOptimizer{}, &routing.DeduplicateParamsOptimizer{})
	if err != nil {
		return nil, err
	}
	response, err := routing.ApplyRulesOptimizers(conf.Routing.Response.Rules, reader, &routing.MergeAndSortRulesOptimizer{}, &routing.DeduplicateParamsOptimizer{})
	if err != nil {
		return nil, err
	}
	var interfaces *network.InterfaceManager
	if services.Interfaces != nil {
		interfaces = services.Interfaces.NewScope()
	} else {
		interfaces, err = network.NewInterfaceManager()
	}
	if err != nil {
		return nil, err
	}
	p, err := policy.New(&conf, request, response, &policy.NewOption{InterfaceManager: interfaces})
	if err != nil {
		interfaces.Close()
		return nil, err
	}
	if err := p.CheckUpstreamsFormat(); err != nil {
		interfaces.Close()
		return nil, err
	}
	r := &Router{policy: p, prefer: prefer, interfaces: interfaces, metrics: newRouterMetrics()}
	for _, upstream := range conf.Upstream {
		name, _ := proxylink.SplitTag(string(upstream))
		r.upstreamNames = append(r.upstreamNames, name)
	}
	if services.Metrics != nil {
		if err := services.Metrics.Register(r.metrics); err != nil {
			_ = r.Close()
			return nil, fmt.Errorf("router metrics: %w", err)
		}
	}
	return r, nil
}

func (r *Router) Close() error {
	if r.interfaces != nil {
		return r.interfaces.Close()
	}
	return nil
}

func (*Router) Plan() plugin.Plan { return plugin.Plan{DNS: []plugin.DNSScope{{}}} }

func (r *Router) ResolveDNS(ctx context.Context, request *plugin.DNSExchange, servers []string) (_ *plugin.DNSResponse, err error) {
	defer func(parent context.Context, started time.Time) {
		r.metrics.request(parent, "resolver", false, err, started)
	}(ctx, time.Now())
	return plugin.RaceDNSServers(ctx, request, servers, func(ctx context.Context, query *plugin.DNSExchange, server string) (*plugin.DNSResponse, error) {
		if !strings.Contains(server, "://") {
			server = "udp://" + server
		}
		raw, err := url.Parse(server)
		if err != nil {
			return nil, err
		}
		upstream, err := policy.NewUpstream(ctx, raw)
		if err != nil {
			return nil, err
		}
		return exchange(ctx, query, upstream, r.metrics, "explicit", "explicit")
	})
}

func (r *Router) WrapDNS(next plugin.DNSHandler) plugin.DNSHandler {
	return func(ctx context.Context, request *plugin.DNSExchange) (response *plugin.DNSResponse, err error) {
		bypass := false
		defer func(started time.Time) { r.metrics.request(ctx, "middleware", bypass, err, started) }(time.Now())
		// An earlier plugin's explicit server assignment takes precedence over
		// general upstream policy, but still uses the ordinary routed dial service.
		if !request.Replayable() || request.ServerAssigned {
			bypass = true
			return next(ctx, request)
		}
		query := request.MessageCopy()
		q := query.Question[0]
		if r.prefer == 0 || q.Qtype == r.prefer || q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
			return r.resolve(ctx, request, next, "query")
		}
		preferred := request.Fork()
		query.Question[0].Qtype = r.prefer
		preferred.DNSPacket = plugin.DNSMessage(query)
		probeCtx, cancelProbe := context.WithTimeout(ctx, partialBudget(ctx))
		defer cancelProbe()
		var probe *plugin.DNSResponse
		var probeErr error
		var wg sync.WaitGroup
		wg.Go(func() { probe, probeErr = r.resolve(probeCtx, preferred, next, "probe") })
		response, err = r.resolve(ctx, request, next, "query")
		if err != nil {
			cancelProbe()
		}
		wg.Wait()
		message := responseMessage(preferred, probe)
		if err == nil && probeErr == nil && message != nil && !message.Truncated && message.Rcode == dns.RcodeSuccess && responseMessage(request, response) != nil {
			for _, rr := range message.Answer {
				if rr.Header().Rrtype == r.prefer {
					if r.metrics != nil {
						family := "ipv6"
						if q.Qtype == dns.TypeA {
							family = "ipv4"
						}
						r.metrics.suppressions.WithLabelValues(family).Inc()
					}
					return emptyResponse(request), nil
				}
			}
		}
		return response, err
	}
}

// Optional work leaves time for the requested answer or the next transport.
func partialBudget(ctx context.Context) time.Duration {
	budget := consts.DefaultDNSRetryInterval
	if deadline, ok := ctx.Deadline(); ok {
		budget = min(budget, time.Until(deadline)/2)
	}
	return budget
}

// Policy operates on a private, correlated view. Header-only errors borrow the
// request question for matching; accepting them still returns the original wire.
// Invalid/uncorrelated asis frames remain transparent and cannot drive policy.
func responseMessage(request *plugin.DNSExchange, response *plugin.DNSResponse) *dns.Msg {
	if response == nil {
		return nil
	}
	message := response.MessageCopy()
	query := request.MessageCopy()
	if message == nil || query == nil {
		return nil
	}
	if netutils.ValidateDnsResponseAllowEmptyQuestion(query, message, query.Id) != nil {
		return nil
	}
	return message
}

func emptyResponse(request *plugin.DNSExchange) *plugin.DNSResponse {
	m := new(dns.Msg).SetReply(request.MessageCopy())
	m.RecursionAvailable = true
	return &plugin.DNSResponse{DNSPacket: plugin.DNSMessage(m), ReceivedAt: time.Now(), Origin: "dns-router:reject"}
}

func (r *Router) resolve(ctx context.Context, request *plugin.DNSExchange, next plugin.DNSHandler, purpose string) (*plugin.DNSResponse, error) {
	q := request.MessageCopy().Question[0]
	index, err := r.policy.RequestSelect(q.Name, q.Qtype, request.Interface, request.OriginalDestination.Addr(), request.Source.Addr())
	if err != nil {
		return nil, err
	}
	if index == policy.DnsRequestOutboundIndex_Reject {
		r.metrics.decision("request", "reject", purpose)
		return emptyResponse(request), nil
	}
	if index == policy.DnsRequestOutboundIndex_AsIs {
		r.metrics.decision("request", "asis", purpose)
	} else {
		r.metrics.decision("request", "upstream", purpose)
	}
	for range policy.MaxDnsLookupDepth {
		var response *plugin.DNSResponse
		if index == policy.DnsRequestOutboundIndex_AsIs {
			response, err = next(ctx, request)
		} else {
			var upstream *policy.Upstream
			upstream, err = r.policy.GetUpstream(ctx, index)
			if err == nil {
				response, err = exchange(ctx, request, upstream, r.metrics, r.upstreamNames[int(index)], purpose)
			}
		}
		if err != nil || response == nil {
			return response, err
		}
		message := responseMessage(request, response)
		if message == nil {
			return response, nil
		}
		selected, err := r.policy.ResponseSelect(message, index)
		if err != nil {
			return nil, err
		}
		switch selected {
		case policy.DnsResponseOutboundIndex_Accept:
			r.metrics.decision("response", "accept", purpose)
			return response, nil
		case policy.DnsResponseOutboundIndex_Reject:
			r.metrics.decision("response", "reject", purpose)
			return emptyResponse(request), nil
		default:
			r.metrics.decision("response", "reroute", purpose)
			index = policy.DnsRequestOutboundIndex(selected)
		}
	}
	return nil, errors.New("DNS response routing exceeded lookup depth")
}

type requestDialer struct {
	request  *plugin.DNSExchange
	hostname string
}

func (d requestDialer) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	return d.request.DialContext(ctx, network, target, d.hostname)
}
func (d requestDialer) ListenPacket(ctx context.Context, target string) (net.PacketConn, error) {
	return d.request.ListenPacket(ctx, target, d.hostname)
}

// Exchange is also available to plugins implementing server assignments. Every
// exchange is routed with the original client's identity by dae's dial services.
func Exchange(ctx context.Context, request *plugin.DNSExchange, upstream *policy.Upstream) (*plugin.DNSResponse, error) {
	return exchange(ctx, request, upstream, nil, "", "")
}

func exchange(ctx context.Context, request *plugin.DNSExchange, upstream *policy.Upstream, metrics *routerMetrics, name, purpose string) (*plugin.DNSResponse, error) {
	query := request.MessageCopy()
	versions, protocols := upstream.SupportedNetworks()
	var last error
	for v, version := range versions {
		ip := upstream.Ip4
		if version == consts.IpVersionStr_6 {
			ip = upstream.Ip6
		}
		var truncated *plugin.DNSResponse
		for i, protocol := range protocols {
			operation := ctx
			cancel := func() {}
			if i+1 < len(protocols) || v+1 < len(versions) {
				operation, cancel = context.WithTimeout(ctx, partialBudget(ctx))
			}
			started := time.Now()
			message, err := transport.Exchange(operation, upstream, requestDialer{request, upstream.Hostname}, netip.AddrPortFrom(ip, upstream.Port), string(protocol), query)
			transportName := string(upstream.Scheme)
			if upstream.Scheme == policy.UpstreamScheme_TCP_UDP {
				transportName = string(protocol)
			}
			metrics.attempt(operation, name, transportName, purpose, err, message != nil && message.Truncated, started)
			cancel()
			if err == nil {
				response := &plugin.DNSResponse{DNSPacket: plugin.DNSMessage(message), ReceivedAt: time.Now(), Origin: upstream.String()}
				if !message.Truncated || i+1 == len(protocols) {
					return response, nil
				}
				truncated = response
			} else {
				last = err
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		if truncated != nil {
			return truncated, nil
		}
	}
	return nil, fmt.Errorf("DNS exchange with %s: %w", upstream, last)
}
