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
	"reflect"
	"strings"
	"sync"
	"time"

	policy "github.com/daeuniverse/dae-plugin-dns-router/policy"
	"github.com/daeuniverse/dae-plugin-dns-router/transport"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/network"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	dns "github.com/miekg/dns"
)

var Plugin = plugin.Definition{Setup: Setup, Validate: Validate}

type Router struct {
	policy     *policy.Dns
	prefer     uint16
	interfaces *network.InterfaceManager
}

func Validate(spec plugin.Spec) error {
	_, _, err := parseSettings(spec)
	return err
}

func parseSettings(spec plugin.Spec) (policy.Config, uint16, error) {
	conf := policy.Config{}
	if err := config.SectionParser(reflect.ValueOf(&conf), spec.Config); err != nil {
		return conf, 0, err
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
		name, link := common.GetTagFromLinkLikePlaintext(string(upstream))
		if name == "" {
			return conf, 0, errors.New("DNS upstream requires a tag")
		}
		raw, err := url.Parse(link)
		if err != nil {
			return conf, 0, fmt.Errorf("upstream %q: invalid URL", name)
		}
		if _, _, _, _, err := policy.ParseRawUpstream(raw); err != nil {
			return conf, 0, fmt.Errorf("upstream %q: %w", name, err)
		}
	}
	return conf, prefer, policy.Validate(&conf)
}

func Setup(ctx context.Context, spec plugin.Spec, services plugin.Services) (plugin.Plugin, error) {
	conf, prefer, err := parseSettings(spec)
	if err != nil {
		return nil, err
	}
	reader := routing.NewDatReaderOptimizer(ctx, assets.NewLocationFinder([]string{services.BaseDir}))
	request, err := routing.ApplyRulesOptimizers(conf.Routing.Request.Rules, &routing.AliasOptimizer{}, reader, &routing.MergeAndSortRulesOptimizer{}, &routing.DeduplicateParamsOptimizer{})
	if err != nil {
		return nil, err
	}
	response, err := routing.ApplyRulesOptimizers(conf.Routing.Response.Rules, reader, &routing.MergeAndSortRulesOptimizer{}, &routing.DeduplicateParamsOptimizer{})
	if err != nil {
		return nil, err
	}
	interfaces, err := network.NewInterfaceManager()
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
	return &Router{policy: p, prefer: prefer, interfaces: interfaces}, nil
}

func (r *Router) Close() error {
	if r.interfaces != nil {
		return r.interfaces.Close()
	}
	return nil
}

func (*Router) Plan() plugin.Plan { return plugin.Plan{DNS: []plugin.DNSScope{{}}} }

func (*Router) ResolveDNS(ctx context.Context, request *plugin.DNSRequest, servers []string) (*plugin.DNSResponse, error) {
	if len(servers) == 0 || len(servers) > 16 {
		return nil, fmt.Errorf("expected 1..16 DNS servers")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		response *plugin.DNSResponse
		err      error
	}
	results := make(chan result, len(servers))
	var wg sync.WaitGroup
	defer wg.Wait()
	for _, server := range servers {
		wg.Go(func() {
			if !strings.Contains(server, "://") {
				if ip, err := netip.ParseAddr(server); err == nil {
					server = netip.AddrPortFrom(ip, 53).String()
				}
				server = "udp://" + server
			}
			raw, err := url.Parse(server)
			var response *plugin.DNSResponse
			if err == nil {
				var upstream *policy.Upstream
				upstream, err = policy.NewUpstream(ctx, raw)
				if err == nil {
					response, err = Exchange(ctx, request, upstream)
				}
			}
			results <- result{response, err}
		})
	}
	var failures error
	for range servers {
		result := <-results
		if result.err == nil && result.response != nil {
			cancel()
			return result.response, nil
		}
		failures = errors.Join(failures, result.err)
	}
	return nil, failures
}

func (r *Router) WrapDNS(next plugin.DNSHandler) plugin.DNSHandler {
	return func(ctx context.Context, request *plugin.DNSRequest) (*plugin.DNSResponse, error) {
		if !replayable(request.Message) {
			return next(ctx, request)
		}
		// An earlier plugin's explicit server assignment takes precedence over
		// general upstream policy, but still uses the ordinary routed dial service.
		if request.ServerAssigned {
			return next(ctx, request)
		}
		q := request.Message.Question[0]
		if r.prefer == 0 || q.Qtype == r.prefer || q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
			return r.resolve(ctx, request, next)
		}
		preferred := request.Copy()
		preferred.Independent = true
		preferred.Message.Question[0].Qtype = r.prefer
		preferred.Wire, _ = preferred.Message.Pack()
		probeCtx, cancelProbe := context.WithTimeout(ctx, partialBudget(ctx))
		defer cancelProbe()
		var probe *plugin.DNSResponse
		var probeErr error
		var wg sync.WaitGroup
		wg.Go(func() { probe, probeErr = r.resolve(probeCtx, preferred, next) })
		response, err := r.resolve(ctx, request, next)
		if err != nil {
			cancelProbe()
		}
		wg.Wait()
		message := responseMessage(preferred, probe)
		if err == nil && probeErr == nil && message != nil && !message.Truncated && message.Rcode == dns.RcodeSuccess && responseMessage(request, response) != nil {
			for _, rr := range message.Answer {
				if rr.Header().Rrtype == r.prefer {
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
func responseMessage(request *plugin.DNSRequest, response *plugin.DNSResponse) *dns.Msg {
	if response == nil {
		return nil
	}
	var message *dns.Msg
	if len(response.Wire) != 0 {
		message = new(dns.Msg)
		if netutils.UnpackDnsMessage(response.Wire, message) != nil {
			return nil
		}
	} else if response.Message != nil {
		message = response.Message.Copy()
	} else {
		return nil
	}
	if netutils.ValidateDnsResponseAllowEmptyQuestion(request.Message, message, request.Message.Id) != nil {
		return nil
	}
	return message
}

func replayable(message *dns.Msg) bool {
	if message == nil || message.Response || message.Opcode != dns.OpcodeQuery || len(message.Question) != 1 {
		return false
	}
	for _, rr := range message.Extra {
		if rr.Header().Rrtype == dns.TypeTSIG || rr.Header().Rrtype == dns.TypeSIG {
			return false
		}
	}
	q := message.Question[0]
	return q.Qtype != dns.TypeAXFR && q.Qtype != dns.TypeIXFR && q.Qtype != dns.TypeTKEY
}

func emptyResponse(request *plugin.DNSRequest) *plugin.DNSResponse {
	m := new(dns.Msg).SetReply(request.Message)
	m.RecursionAvailable = true
	return &plugin.DNSResponse{Message: m, ReceivedAt: time.Now(), Origin: "dns-router:reject"}
}

func (r *Router) resolve(ctx context.Context, request *plugin.DNSRequest, next plugin.DNSHandler) (*plugin.DNSResponse, error) {
	q := request.Message.Question[0]
	index, err := r.policy.RequestSelect(q.Name, q.Qtype, request.Interface, request.OriginalDestination.Addr(), request.Source.Addr())
	if err != nil {
		return nil, err
	}
	if index == policy.DnsRequestOutboundIndex_Reject {
		return emptyResponse(request), nil
	}
	for depth := 0; depth < policy.MaxDnsLookupDepth; depth++ {
		var response *plugin.DNSResponse
		if index == policy.DnsRequestOutboundIndex_AsIs {
			response, err = next(ctx, request)
		} else {
			var upstream *policy.Upstream
			upstream, err = r.policy.GetUpstream(ctx, index)
			if err == nil {
				response, err = Exchange(ctx, request, upstream)
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
			return response, nil
		case policy.DnsResponseOutboundIndex_Reject:
			return emptyResponse(request), nil
		default:
			index = policy.DnsRequestOutboundIndex(selected)
		}
	}
	return nil, errors.New("DNS response routing exceeded lookup depth")
}

type requestDialer struct {
	request  *plugin.DNSRequest
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
func Exchange(ctx context.Context, request *plugin.DNSRequest, upstream *policy.Upstream) (*plugin.DNSResponse, error) {
	versions, protocols := upstream.SupportedNetworks()
	var last error
	for _, version := range versions {
		ip := upstream.Ip4
		if version == consts.IpVersionStr_6 {
			ip = upstream.Ip6
		}
		var truncated *plugin.DNSResponse
		for i, protocol := range protocols {
			operation := ctx
			cancel := func() {}
			if i+1 < len(protocols) {
				operation, cancel = context.WithTimeout(ctx, partialBudget(ctx))
			}
			forwarder, err := transport.New(ctx, upstream, requestDialer{request, upstream.Hostname}, netip.AddrPortFrom(ip, upstream.Port), string(protocol))
			if err != nil {
				cancel()
				return nil, err
			}
			message := request.Message.Copy()
			err = forwarder.ForwardDNS(operation, message)
			cancel()
			_ = forwarder.Close()
			if err == nil {
				response := &plugin.DNSResponse{Message: message, ReceivedAt: time.Now(), Origin: upstream.String()}
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
