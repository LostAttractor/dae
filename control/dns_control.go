/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	dnsmessage "github.com/miekg/dns"
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
)

// TODO: 在 DNS Config 不变的情况下，保留 DNSCache

const MaxDnsLookupDepth = 3

type IpVersionPrefer int

const (
	IpVersionPrefer_No IpVersionPrefer = 0
	IpVersionPrefer_4  IpVersionPrefer = 4
	IpVersionPrefer_6  IpVersionPrefer = 6
)

type DnsControllerOption struct {
	MatchBitmap       func(fqdn string) []uint32
	DomainRegistry    *DomainRegistry
	BestDialerChooser func(req *udpRequest, upstream *dns.Upstream) (*dialArgument, error)
	IpVersionPrefer   int
	FixedDomainTtl    map[string]int
}

type DnsController struct {
	routing     *dns.Dns
	qtypePrefer uint16

	matchBitmap       func(fqdn string) []uint32
	registry          *DomainRegistry
	bestDialerChooser func(req *udpRequest, upstream *dns.Upstream) (*dialArgument, error)

	fixedDomainTtl    map[string]int
	dnsCache          *commonDnsCache[dnsCacheKey]
	dnsKeyLocker      common.KeyLocker[dnsCacheKey]
	dnsForwarderCache sync.Map // map[dnsForwarderKey]DnsForwarder
	// closed is canceled by Close: once closed, the controller must not serve
	// new requests — its forwarders are closed, and its writes would land on
	// the shared eBPF maps the next control plane owns.
	closed context.Context
	close  context.CancelFunc
}

func parseIpVersionPreference(prefer int) (uint16, error) {
	switch prefer := IpVersionPrefer(prefer); prefer {
	case IpVersionPrefer_No:
		return 0, nil
	case IpVersionPrefer_4:
		return dnsmessage.TypeA, nil
	case IpVersionPrefer_6:
		return dnsmessage.TypeAAAA, nil
	default:
		return 0, fmt.Errorf("unknown preference: %v", prefer)
	}
}

func NewDnsController(routing *dns.Dns, option *DnsControllerOption) (c *DnsController, err error) {
	prefer, err := parseIpVersionPreference(option.IpVersionPrefer)
	if err != nil {
		return nil, err
	}

	closed, close := context.WithCancel(context.Background())
	return &DnsController{
		routing:     routing,
		qtypePrefer: prefer,

		matchBitmap:       option.MatchBitmap,
		registry:          option.DomainRegistry,
		bestDialerChooser: option.BestDialerChooser,

		fixedDomainTtl:    option.FixedDomainTtl,
		dnsForwarderCache: sync.Map{},
		dnsCache:          newCommonDnsCache[dnsCacheKey](32768),
		closed:            closed,
		close:             close,
	}, nil
}

func (c *DnsController) effectiveTTL(fqdn string, ttl int) int {
	if fixedTTL, ok := c.fixedDomainTtl[fqdn]; ok {
		return fixedTTL
	}
	return ttl
}

func (c *DnsController) applyFixedTTL(fqdn string, answers []dnsmessage.RR) {
	fixedTTL, ok := c.fixedDomainTtl[fqdn]
	if !ok {
		return
	}
	var ttl uint32
	if fixedTTL > 0 {
		if uint64(fixedTTL) > uint64(math.MaxUint32) {
			ttl = math.MaxUint32
		} else {
			ttl = uint32(fixedTTL)
		}
	}
	for _, answer := range answers {
		answer.Header().Ttl = ttl
	}
}

func (c *DnsController) UpdateDnsCache(cacheKey dnsCacheKey, fqdn string, answers []dnsmessage.RR) {
	now := time.Now()
	deadlines := make([]time.Time, len(answers))
	for i, answer := range answers {
		if answer == nil {
			deadlines[i] = now
			continue
		}
		ttl := c.effectiveTTL(fqdn, int(answer.Header().Ttl))
		deadlines[i] = now.Add(time.Duration(ttl) * time.Second)
	}
	c.dnsCache.ReplaceDeadlines(cacheKey, answers, deadlines)
}

type udpRequest struct {
	src           netip.AddrPort
	dst           netip.AddrPort
	routingResult *bpfRoutingResult
}

type dialArgument struct {
	networkType common.NetworkType
	Dialer      *dialer.Dialer
	Outbound    *outbound.DialerGroup
	Target      netip.AddrPort
	// mark        uint32
}

type dnsForwarderKey struct {
	upstream     string
	dialArgument dialArgument
}

type queryInfo struct {
	qname string
	qtype uint16
}

type dnsCacheKey struct {
	queryInfo
	dnsForwarderKey
}

func (c *DnsController) prepareQueryInfo(dnsMessage *dnsmessage.Msg) (queryInfo queryInfo) {
	q := dnsMessage.Question[0]
	queryInfo.qname = dnsmessage.CanonicalName(q.Name)
	queryInfo.qtype = q.Qtype
	return
}

func (c *DnsController) Handle(dnsMessage *dnsmessage.Msg, req *udpRequest) (err error) {
	if c.closed.Err() != nil {
		// Drop requests arriving while the owning plane is being retired.
		return nil
	}
	if dnsMessage.Response {
		panic("DNS request expected but DNS response received")
	}

	if len(dnsMessage.Question) == 0 {
		panic("no question in dns message")
	}

	queryInfo := c.prepareQueryInfo(dnsMessage)

	if log.IsLevelEnabled(log.TraceLevel) {
		log.Tracef("Received UDP(DNS) %v <-> %v: %v %v",
			RefineSourceToShow(req.src, req.dst.Addr()), req.dst.String(), queryInfo.qname, queryInfo.qtype,
		)
	}

	id := dnsMessage.Id

	go func() {
		var err error
		// Try to make both A and AAAA lookups.
		if (queryInfo.qtype == dnsmessage.TypeA || queryInfo.qtype == dnsmessage.TypeAAAA) && c.qtypePrefer != 0 {
			dnsMessage2 := dnsMessage.Copy()
			dnsMessage2.Id = uint16(fastrand.Intn(math.MaxUint16))
			// The flipped query must carry its own queryInfo: deriving every
			// downstream key (domain registry, dnsCache, DNS request
			// routing) from the original qtype would file AAAA answers
			// under the A key and break per-family verification.
			queryInfo2 := queryInfo
			switch queryInfo.qtype {
			case dnsmessage.TypeA:
				dnsMessage2.Question[0].Qtype = dnsmessage.TypeAAAA
				queryInfo2.qtype = dnsmessage.TypeAAAA
			case dnsmessage.TypeAAAA:
				dnsMessage2.Question[0].Qtype = dnsmessage.TypeA
				queryInfo2.qtype = dnsmessage.TypeA
			}

			// TODO: ignoreFixedTTL?
			errCh := make(chan error, 1)
			go func() {
				errCh <- c.handleDNSRequest(dnsMessage2, req, queryInfo2)
			}()
			err = oops.Join(c.handleDNSRequest(dnsMessage, req, queryInfo), <-errCh)
			if err != nil {
				goto err
			}
			if c.qtypePrefer != queryInfo.qtype && dnsMessage2 != nil && IncludeAnyIpInMsg(dnsMessage2) {
				c.reject(dnsMessage)
			}
		} else {
			err = c.handleDNSRequest(dnsMessage, req, queryInfo)
		}
	err:
		if err != nil {
			netErr, ok := IsNetError(err)
			err = oops.
				With("Is NetError", ok).
				With("Is Temporary", ok && netErr.Temporary()).
				With("Is Timeout", ok && netErr.Timeout()).
				Wrapf(err, "failed to make dns request")
			if !ok || !netErr.Temporary() {
				log.Warningf("%+v", err)
			}
			return
		}
		if !dnsMessage.Response {
			// No response was produced (a duplicate lookup was dropped, or a
			// soft-failed lookup fell through response routing with the
			// request untouched). Echoing the QR=0 request back would only
			// confuse the client; let it retransmit instead.
			return
		}
		// Keep the id the same with request.
		dnsMessage.Id = id
		dnsMessage.Compress = true
		var data []byte
		if data, err = dnsMessage.Pack(); err != nil {
			log.Errorf("%+v", oops.Wrapf(err, "failed to pack dns message"))
			return
		}
		if err = sendPkt(data, req.dst, req.src); err != nil {
			log.Warningf("%+v", oops.Wrapf(err, "failed to send dns message back"))
		}
	}()

	return nil
}

// TODO: 除了dialSend, 不应该有可预期的 err
// TODO: qname=. qtype=2 的查询是什么, 为什么没有缓存, 因为AsIs?
// TODO: 如果AsIs都不缓存的话，如果一个server可用一个不可用，那就是远端sever的问题?
func (c *DnsController) handleDNSRequest(
	dnsMessage *dnsmessage.Msg,
	req *udpRequest,
	queryInfo queryInfo,
) error {
	RequestIndex, err := c.routing.RequestSelect(
		queryInfo.qname,
		queryInfo.qtype,
		req.routingResult.Ifindex,
		req.dst.Addr(),
		req.src.Addr(),
	)
	if err != nil {
		return err
	}

	if RequestIndex == consts.DnsRequestOutboundIndex_Reject {
		c.reject(dnsMessage)
		return nil
	}

	var upstream *dns.Upstream
	if RequestIndex == consts.DnsRequestOutboundIndex_AsIs {
		// As-is should not be valid in response routing, thus using connection realDest is reasonable.
		upstream = &dns.Upstream{
			Scheme:   "udp",
			Hostname: req.dst.Addr().String(),
			Port:     req.dst.Port(),
			Ip46:     netutils.FromAddr(req.dst.Addr()),
		}
	} else {
		upstream, err = c.routing.GetUpstream(RequestIndex)
		if err != nil {
			return err
		}
	}

	// Dial and re-route
	reqMsg := dnsMessage.Copy()
	responseFromCache := false
Dial:
	for invokingDepth := 1; invokingDepth <= MaxDnsLookupDepth; invokingDepth++ {
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"question": dnsMessage.Question,
				"upstream": upstream.String(),
			}).Debugln("Request to DNS upstream")
		}

		dialArgument, err := c.bestDialerChooser(req, upstream)
		if err != nil {
			return err
		}

		// TODO: 这里可能不可以这样做
		responseFromCache, err = c.dialSend(dnsMessage, upstream, dialArgument, queryInfo)
		if err != nil {
			netErr, ok := IsNetError(err)
			err = oops.
				In("DialContext").
				With("Is NetError", ok).
				With("Is Temporary", ok && netErr.Temporary()).
				With("Is Timeout", ok && netErr.Timeout()).
				Wrapf(err, "DNS dialSend error")
			if !ok {
				return err
			} else if !netErr.Timeout() {
				if dialArgument.Dialer.NeedAliveState() {
					labels := prometheus.Labels{
						"id":       dialArgument.Dialer.StatsID(),
						"outbound": dialArgument.Outbound.Name,
						"subtag":   dialArgument.Dialer.Property.SubscriptionTag,
						"dialer":   dialArgument.Dialer.Name,
						"network":  dialArgument.networkType.String(),
					}
					common.ErrorCount.With(labels).Inc()
					dialArgument.Dialer.ReportUnavailable()
					return err
				}
			}
		}

		ResponseIndex, nextUpstream, err := c.routing.ResponseSelect(dnsMessage, upstream)
		if err != nil {
			return err
		}
		if ResponseIndex.IsReserved() {
			if log.IsLevelEnabled(log.InfoLevel) {
				fields := log.Fields{
					"network":  dialArgument.networkType.String(),
					"outbound": dialArgument.Outbound.Name,
					"policy":   dialArgument.Outbound.GetSelectionPolicy(),
					"dialer":   dialArgument.Dialer.Name,
					"qname":    queryInfo.qname,
					"qtype":    queryInfo.qtype,
					"pid":      req.routingResult.Pid,
					"ifindex":  req.routingResult.Ifindex,
					"dscp":     req.routingResult.Dscp,
					"pname":    ProcessName2String(req.routingResult.Pname[:]),
					"mac":      Mac2String(req.routingResult.Mac[:]),
				}
				switch ResponseIndex {
				case consts.DnsResponseOutboundIndex_Accept:
					log.WithFields(fields).Infof("[DNS] %v <-> %v", RefineSourceToShow(req.src, req.dst.Addr()), RefineAddrPortToShow(dialArgument.Target))
				case consts.DnsResponseOutboundIndex_Reject:
					log.WithFields(fields).Infof("[DNS] %v <-> %v Reject with empty answer", RefineSourceToShow(req.src, req.dst.Addr()), RefineAddrPortToShow(dialArgument.Target))
				}
			}
			switch ResponseIndex {
			case consts.DnsResponseOutboundIndex_Reject:
				// TODO: cache response reject.
				c.reject(dnsMessage)
				fallthrough
			case consts.DnsResponseOutboundIndex_Accept:
				break Dial
			default:
				return oops.Errorf("unknown upstream: %v", ResponseIndex.String())
			}
		}
		if invokingDepth == MaxDnsLookupDepth {
			return oops.Errorf("too deep DNS lookup invoking (depth: %v); there may be infinite loop in your DNS response routing", MaxDnsLookupDepth)
		}
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"question":      dnsMessage.Question,
				"last_upstream": upstream.String(),
				"next_upstream": nextUpstream.String(),
			}).Debugln("Change DNS upstream and resend")
		}
		upstream = nextUpstream
		*dnsMessage = *reqMsg
	}
	// TODO: dial_mode: domain 的逻辑失效问题
	// TODO: 我们现在缓存了它, 但并不响应缓存, 这是一个workround, 会导致污染其他非AsIs的查询
	// TODO: AsIs也需要更新domain_routing_map? 不然没有办法sniff, 并且考虑到有些应用会使用不同的DNS, 必须对全部 upstream 更新
	// TODO: RemoveCache
	// TODO: 不再存储Bitmap, 提高更新代码可读性
	// 但在有bump_map的情况下这不是大问题
	// TOOD: 细分日志
	switch {
	case !dnsMessage.Response,
		len(dnsMessage.Answer) == 0,
		len(dnsMessage.Question) == 0,               // Check healthy resp.
		dnsMessage.Rcode != dnsmessage.RcodeSuccess: // Check suc resp.
		return nil
	}

	c.finalizeAcceptedResponse(queryInfo, dnsMessage, responseFromCache)
	return nil
}

// finalizeAcceptedResponse applies upstream-only side effects. Cached answers
// already carry their remaining effective TTL from FillInto, and their domain
// registrations were created by the original upstream response; treating a
// hit as fresh would restart both lifetimes without revalidation.
func (c *DnsController) finalizeAcceptedResponse(queryInfo queryInfo, msg *dnsmessage.Msg, fromCache bool) {
	if fromCache {
		return
	}
	ans := CopyDnsAnswers(msg.Answer)
	c.registerAnswers(queryInfo, ans)
	c.applyFixedTTL(queryInfo.qname, msg.Answer)
}

// registerAnswers registers every A/AAAA record of a DNS response in the
// domain registry. The registry is the single source of truth that keeps
// the kernel domain routing maps and sniff verification in sync with what
// clients resolved; it owns all GC and kernel-map accounting.
//
// fixed_ttl, when configured, is the effective TTL for both the response
// cache and registry lifetimes. The registry floors it at MinDomainTTL, so a
// zero fixed TTL still updates kernel routing while forcing every client DNS
// query back to the upstream.
func (c *DnsController) registerAnswers(queryInfo queryInfo, answers []dnsmessage.RR) {
	c.registerAnswersInternal(queryInfo, answers, false)
}

// registerAnswersNoExpiry keeps synthetic DNS-upstream addresses registered
// without a time-based deadline. Their RR headers intentionally retain TTL 0
// because this lifetime is internal and is never sent to clients.
func (c *DnsController) registerAnswersNoExpiry(queryInfo queryInfo, answers []dnsmessage.RR) {
	c.registerAnswersInternal(queryInfo, answers, true)
}

func (c *DnsController) registerAnswersInternal(queryInfo queryInfo, answers []dnsmessage.RR, noExpiry bool) {
	if c.closed.Err() != nil {
		// Do not write the shared eBPF maps after Close; the next control
		// plane owns them now.
		return
	}
	// The match bitmap only depends on the domain, so it is shared by all
	// records of this answer set.
	domainBitmap := c.matchBitmap(queryInfo.qname)
	now := time.Now()
	for _, answer := range answers {
		var ip netip.Addr
		var ok bool
		switch body := answer.(type) {
		case *dnsmessage.A:
			ip, ok = netip.AddrFromSlice(body.A)
		case *dnsmessage.AAAA:
			ip, ok = netip.AddrFromSlice(body.AAAA)
		}
		if !ok || ip.IsUnspecified() {
			continue
		}
		if noExpiry {
			c.registry.UpsertNoExpiry(queryInfo, ip, domainBitmap, now)
			continue
		}
		ttl := int(answer.Header().Ttl)
		ttl = c.effectiveTTL(queryInfo.qname, ttl)
		c.registry.Upsert(queryInfo, ip, domainBitmap, ttl, now)
	}
}

func (c *DnsController) reject(msg *dnsmessage.Msg) {
	msg.Answer = []dnsmessage.RR{}
	msg.Rcode = dnsmessage.RcodeSuccess
	msg.Response = true
	msg.RecursionAvailable = true
	msg.Truncated = false
}

// TODO: 简化 cacheKey?
func (c *DnsController) dialSend(msg *dnsmessage.Msg, upstream *dns.Upstream, dialArgument *dialArgument, queryInfo queryInfo) (bool, error) {
	if c.closed.Err() != nil {
		// The cached forwarders are closed by Close; dialing here would
		// recreate connections nobody closes anymore.
		return false, net.ErrClosed
	}
	key := dnsForwarderKey{upstream: upstream.String(), dialArgument: *dialArgument}
	cacheKey := dnsCacheKey{queryInfo: queryInfo, dnsForwarderKey: key}

	// No parallel for the same lookup.
	l, isNew := c.dnsKeyLocker.Lock(cacheKey)
	defer c.dnsKeyLocker.Unlock(cacheKey, l)
	var forwarder DnsForwarder
	value, ok := c.dnsForwarderCache.Load(key)
	if ok {
		if cache := c.dnsCache.Get(cacheKey); cache != nil {
			if FillInto(msg, cache) {
				if log.IsLevelEnabled(log.DebugLevel) && len(msg.Question) > 0 {
					log.WithFields(log.Fields{
						"qname":  queryInfo.qname,
						"qtype":  queryInfo.qtype,
						"rcode":  msg.Rcode,
						"answer": FormatDnsRsc(msg.Answer),
					}).Debugf("UDP(DNS) <-> Cache")
				}
				return true, nil
			}
		}
		if !isNew {
			if log.IsLevelEnabled(log.DebugLevel) {
				log.Debugf("UDP(DNS) <-> Drop failed duplicate lookup: %v %v", queryInfo.qname, queryInfo.qtype)
			}
			return false, nil
		}
		forwarder = value.(DnsForwarder)
	} else {
		var err error
		forwarder, err = newDnsForwarder(upstream, *dialArgument)
		if err != nil {
			return false, err
		}
		// Try to store the new forwarder, but use LoadOrStore to handle concurrent creation
		actualValue, _ := c.dnsForwarderCache.LoadOrStore(key, forwarder)
		forwarder = actualValue.(DnsForwarder)
	}

	err := forwarder.ForwardDNS(msg)
	if err != nil {
		return false, err
	}

	// TODO: 直接加入到上面的日志
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"qname":  queryInfo.qname,
			"qtype":  queryInfo.qtype,
			"rcode":  msg.Rcode,
			"answer": FormatDnsRsc(msg.Answer),
		}).Debugf("UDP(DNS) <-> %v", dialArgument.Target.String())
	}

	// TODO: 细分日志
	switch {
	case !msg.Response,
		len(msg.Question) == 0,               // Check healthy resp.
		msg.Rcode != dnsmessage.RcodeSuccess: // Check suc resp.
		log.WithFields(log.Fields{
			"qname":  queryInfo.qname,
			"qtype":  queryInfo.qtype,
			"rcode":  msg.Rcode,
			"answer": FormatDnsRsc(msg.Answer),
		}).Tracef("Not a valid DNS response")
		return false, nil
	}

	// TODO: 不缓存ans为空的响应?
	ans := CopyDnsAnswers(msg.Answer)
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"qname":    queryInfo.qname,
			"qtype":    queryInfo.qtype,
			"rcode":    msg.Rcode,
			"ans":      FormatDnsRsc(ans),
			"upstream": cacheKey.upstream,
			"dialer":   cacheKey.dialArgument.Dialer.Name,
			"outbound": cacheKey.dialArgument.Outbound.Name,
		}).Debugf("Update DNS record cache")
	}
	c.UpdateDnsCache(cacheKey, queryInfo.qname, ans)

	return false, nil
}

func (c *DnsController) Close() error {
	// Cancel first: registerAnswers/dialSend check closed, so no new registry
	// writes or dials can start while the forwarders are closed below.
	c.close()

	// Close all DNS forwarders
	c.dnsForwarderCache.Range(func(key, value any) bool {
		if forwarder, ok := value.(io.Closer); ok {
			forwarder.Close()
		}
		return true
	})
	return nil
}
