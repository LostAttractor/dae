/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"io"
	"math"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/netutils"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	dnsmessage "github.com/miekg/dns"
	"github.com/mohae/deepcopy"
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
)

// TODO: Lookup Cache 的 GC
// TODO: reload时保留lookup cache

const (
	MaxDnsLookupDepth = 3
	minLookupTTL      = 86400
)

type IpVersionPrefer int

const (
	IpVersionPrefer_No IpVersionPrefer = 0
	IpVersionPrefer_4  IpVersionPrefer = 4
	IpVersionPrefer_6  IpVersionPrefer = 6
)

var (
	UnspecifiedAddressA        = netip.MustParseAddr("0.0.0.0")
	UnspecifiedAddressAAAA     = netip.MustParseAddr("::")
	ErrUnsupportedQuestionType = fmt.Errorf("unsupported question type")
)

type DnsControllerOption struct {
	MatchBitmap        func(fqdn string) []uint32
	NewLookupCache     func(ip netip.Addr, domainBitmap []uint32) error
	LookupCacheTimeout func(ip netip.Addr, domainBitmap []uint32) error
	BestDialerChooser  func(req *udpRequest, upstream *dns.Upstream) (*dialArgument, error)
	IpVersionPrefer    int
	FixedDomainTtl     map[string]int
}

type DnsController struct {
	routing     *dns.Dns
	qtypePrefer uint16

	matchBitmap        func(fqdn string) []uint32
	newLookupCache     func(ip netip.Addr, domainBitmap []uint32) error
	lookupCacheTimeout func(ip netip.Addr, domainBitmap []uint32) error
	bestDialerChooser  func(req *udpRequest, upstream *dns.Upstream) (*dialArgument, error)

	fixedDomainTtl    map[string]int
	lookupCache       *commonDnsCache[queryInfo]
	dnsCache          *commonDnsCache[dnsCacheKey]
	dnsKeyLocker      common.KeyLocker[dnsCacheKey]
	dnsForwarderCache sync.Map // map[dnsForwarderKey]DnsForwarder
	// mu protects deadlineTimers
	mu             sync.Mutex
	deadlineTimers map[*DnsCache]*time.Timer
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
	// Parse ip version preference.
	prefer, err := parseIpVersionPreference(option.IpVersionPrefer)
	if err != nil {
		return nil, err
	}

	return &DnsController{
		routing:     routing,
		qtypePrefer: prefer,

		matchBitmap:        option.MatchBitmap,
		newLookupCache:     option.NewLookupCache,
		lookupCacheTimeout: option.LookupCacheTimeout,
		bestDialerChooser:  option.BestDialerChooser,

		fixedDomainTtl:    option.FixedDomainTtl,
		dnsForwarderCache: sync.Map{},
		dnsCache:          newCommonDnsCache[dnsCacheKey](32768),
		lookupCache:       newCommonDnsCache[queryInfo](16384),
		deadlineTimers:    make(map[*DnsCache]*time.Timer),
	}, nil
}

func (c *DnsController) NormalizeDnsResp(answers []dnsmessage.RR) (ttl int) {
	// Get TTL.
	for _, ans := range answers {
		if ttl == 0 {
			ttl = int(ans.Header().Ttl)
			break
		}
	}

	// Set TTL = zero. This requests applications must resend every request.
	// However, it may be not defined in the standard.
	for i := range answers {
		answers[i].Header().Ttl = 0
	}
	return
}

func (c *DnsController) UpdateDnsCacheDeadline(cacheKey dnsCacheKey, fqdn string, answers []dnsmessage.RR, deadline time.Time) {
	if fixedTtl, ok := c.fixedDomainTtl[fqdn]; ok {
		deadline = time.Now().Add(time.Duration(fixedTtl) * time.Second)
	}
	for _, answer := range answers {
		c.dnsCache.UpdateDeadline(cacheKey, answer, deadline)
	}
}

func (c *DnsController) UpdateDnsCacheTtl(cacheKey dnsCacheKey, fqdn string, answers []dnsmessage.RR, ttl int) {
	finalTTL := ttl
	if fixedTtl, ok := c.fixedDomainTtl[fqdn]; ok {
		finalTTL = fixedTtl
	}
	for _, answer := range answers {
		c.dnsCache.UpdateTtl(cacheKey, answer, finalTTL)
	}
}

type udpRequest struct {
	src           netip.AddrPort
	dst           netip.AddrPort
	routingResult *bpfRoutingResult
}

type dialArgument struct {
	networkType dialer.NetworkType
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
	if len(dnsMessage.Question) != 0 {
		q := dnsMessage.Question[0]
		queryInfo.qname = dnsmessage.CanonicalName(q.Name)
		queryInfo.qtype = q.Qtype
	}
	return
}

func (c *DnsController) Handle(dnsMessage *dnsmessage.Msg, req *udpRequest) (err error) {
	if log.IsLevelEnabled(log.TraceLevel) && len(dnsMessage.Question) > 0 {
		q := dnsMessage.Question[0]
		log.Tracef("Received UDP(DNS) %v <-> %v: %v %v",
			RefineSourceToShow(req.src, req.dst.Addr()), req.dst.String(), strings.ToLower(q.Name), QtypeToString(q.Qtype),
		)
	}

	if dnsMessage.Response {
		return fmt.Errorf("DNS request expected but DNS response received")
	}

	queryInfo := c.prepareQueryInfo(dnsMessage)
	id := dnsMessage.Id

	go func() {
		var err error
		// Check ip version preference and qtype.
		switch queryInfo.qtype {
		case dnsmessage.TypeA, dnsmessage.TypeAAAA:
			if c.qtypePrefer == 0 {
				err = c.handleDNSRequest(dnsMessage, req, queryInfo)
			} else {
				// Try to make both A and AAAA lookups.
				dnsMessage2 := deepcopy.Copy(dnsMessage).(*dnsmessage.Msg)
				dnsMessage2.Id = uint16(fastrand.Intn(math.MaxUint16))
				switch queryInfo.qtype {
				case dnsmessage.TypeA:
					dnsMessage2.Question[0].Qtype = dnsmessage.TypeAAAA
				case dnsmessage.TypeAAAA:
					dnsMessage2.Question[0].Qtype = dnsmessage.TypeA
				}

				// TODO: ignoreFixedTTL?
				errCh := make(chan error, 1)
				go func() {
					err = c.handleDNSRequest(dnsMessage2, req, queryInfo)
					errCh <- err
				}()
				err = oops.Join(c.handleDNSRequest(dnsMessage, req, queryInfo), <-errCh)
				if err != nil {
					break
				}
				if c.qtypePrefer != queryInfo.qtype && dnsMessage2 != nil && IncludeAnyIpInMsg(dnsMessage2) {
					c.reject(dnsMessage)
				}
			}
		default:
			err = c.handleDNSRequest(dnsMessage, req, queryInfo)
		}
		if err != nil {
			var netErr net.Error
			err = oops.
				With("Is NetError", errors.As(err, &netErr)).
				With("Is Temporary", netErr != nil && netErr.Temporary()).
				With("Is Timeout", netErr != nil && netErr.Timeout()).
				Wrapf(err, "failed to make dns request")
			// TODO: 不是neterr也需要展示, 需要同步这个行为到其他代码
			if errors.As(err, &netErr) {
				if !netErr.Temporary() {
					log.Warningf("%+v", err)
				}
			} else {
				log.Warningf("%+v", err)
			}
			return
		}
		// Keep the id the same with request.
		dnsMessage.Id = id
		dnsMessage.Compress = true
		var data []byte
		if data, err = dnsMessage.Pack(); err != nil {
			log.Errorf("%+v", oops.Wrapf(err, "failed to pack dns message"))
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
	// Route Requset
	RequestIndex, err := c.routing.RequestSelect(queryInfo.qname, queryInfo.qtype)
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
		// Get corresponding upstream.
		upstream, err = c.routing.GetUpstream(RequestIndex)
		if err != nil {
			return err
		}
	}

	// Dial and re-route
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"question": dnsMessage.Question,
			"upstream": upstream.String(),
		}).Debugln("Request to DNS upstream")
	}

Dial:
	for invokingDepth := 1; invokingDepth <= MaxDnsLookupDepth; invokingDepth++ {
		// Select best dial arguments (outbound, dialer, l4proto, ipversion, etc.)
		dialArgument, err := c.bestDialerChooser(req, upstream)
		if err != nil {
			return err
		}

		// TODO: 这里可能不可以这样做
		err = c.dialSend(dnsMessage, upstream, dialArgument, queryInfo)
		if err != nil {
			var netErr net.Error
			err = oops.
				With("Is NetError", errors.As(err, &netErr)).
				With("Is Temporary", netErr != nil && netErr.Temporary()).
				With("Is Timeout", netErr != nil && netErr.Timeout()).
				Wrapf(err, "DNS dialSend error")
			if errors.As(err, &netErr) && !netErr.Temporary() {
				dialArgument.Dialer.ReportUnavailable(&dialArgument.networkType, err)
			}
			return err
		}

		// Route response.
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
					log.WithFields(fields).Infof("[DNS] %v <-> %v", RefineSourceToShow(req.src, req.dst.Addr()), RefineAddrPortToShow(dialArgument.Target))
				}
			}
			switch ResponseIndex {
			case consts.DnsResponseOutboundIndex_Accept:
				// Accept.
				break Dial
			case consts.DnsResponseOutboundIndex_Reject:
				// Reject
				// TODO: cache response reject.
				c.reject(dnsMessage)
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
	}
	// TODO: dial_mode: domain 的逻辑失效问题
	// TODO: 我们现在缓存了它, 但并不响应缓存, 这是一个workround, 会导致污染其他非AsIs的查询
	// TODO: AsIs也需要更新domain_routing_map? 不然没有办法sniff, 并且考虑到有些应用会使用不同的DNS, 必须对全部 upstream 更新
	// TODO: RemoveCache
	// TODO: 不再存储Bitmap, 提高更新代码可读性
	// 但在有bump_map的情况下这不是大问题
	switch {
	case !dnsMessage.Response,
		len(dnsMessage.Answer) == 0,
		len(dnsMessage.Question) == 0,               // Check healthy resp.
		dnsMessage.Rcode != dnsmessage.RcodeSuccess: // Check suc resp.
		return nil
	}

	ans := deepcopy.Copy(dnsMessage.Answer).([]dnsmessage.RR)
	ttl := c.NormalizeDnsResp(ans)
	c.LookupCache(queryInfo, ans, ttl)
	return nil
}

func (c *DnsController) LookupCache(queryInfo queryInfo, answers []dnsmessage.RR, ttl int) error {
	domainBitmap := c.matchBitmap(queryInfo.qname)
	allZero := true
	for _, v := range domainBitmap {
		if v != 0 {
			allZero = false
			break
		}
	}
	lookupTTL := ttl
	if lookupTTL < minLookupTTL {
		lookupTTL = minLookupTTL
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, answer := range answers {
		cache := c.lookupCache.UpdateTtl(queryInfo, answer, ttl)
		ip, ok := cache.GetIp()
		if !ok || allZero {
			continue
		}
		if timer, ok := c.deadlineTimers[cache]; ok {
			timer.Reset(time.Duration(lookupTTL) * time.Second)
			continue
		}
		err := c.newLookupCache(ip, domainBitmap)
		if err != nil {
			return err
		}
		c.deadlineTimers[cache] = time.AfterFunc(time.Duration(lookupTTL)*time.Second, func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.lookupCacheTimeout(ip, domainBitmap)
			delete(c.deadlineTimers, cache)
		})
	}
	return nil
}

func (c *DnsController) reject(msg *dnsmessage.Msg) {
	// Reject with empty answer.
	msg.Answer = []dnsmessage.RR{}
	msg.Rcode = dnsmessage.RcodeSuccess
	msg.Response = true
	msg.RecursionAvailable = true
	msg.Truncated = false
}

// TODO: 简化 cacheKey?
func (c *DnsController) dialSend(msg *dnsmessage.Msg, upstream *dns.Upstream, dialArgument *dialArgument, queryInfo queryInfo) error {
	/// Dial and send.
	// get forwarder from cache
	key := dnsForwarderKey{upstream: upstream.String(), dialArgument: *dialArgument}
	cacheKey := dnsCacheKey{queryInfo: queryInfo, dnsForwarderKey: key}
	// No parallel for the same lookup.
	l := c.dnsKeyLocker.Lock(cacheKey)
	defer c.dnsKeyLocker.Unlock(cacheKey, l)
	var forwarder DnsForwarder
	value, ok := c.dnsForwarderCache.Load(key)
	if ok {
		// Lookup Cache
		if cache := c.dnsCache.Get(cacheKey); cache != nil {
			if !c.dnsCache.AllTimeout(cache) {
				FillInto(msg, cache)
				if log.IsLevelEnabled(log.DebugLevel) && len(msg.Question) > 0 {
					log.WithFields(log.Fields{
						"answer": msg.Answer,
					}).Debugf("UDP(DNS) <-> Cache: %v %v", queryInfo.qname, queryInfo.qtype)
				}
				return nil
			}
		}
		forwarder = value.(DnsForwarder)
	} else {
		var err error
		forwarder, err = newDnsForwarder(upstream, *dialArgument)
		if err != nil {
			return err
		}
		// Try to store the new forwarder, but use LoadOrStore to handle concurrent creation
		actualValue, _ := c.dnsForwarderCache.LoadOrStore(key, forwarder)
		forwarder = actualValue.(DnsForwarder)
	}

	err := forwarder.ForwardDNS(msg)
	if err != nil {
		return err
	}

	switch {
	case !msg.Response,
		len(msg.Question) == 0,               // Check healthy resp.
		msg.Rcode != dnsmessage.RcodeSuccess: // Check suc resp.
		return nil
	}

	ans := deepcopy.Copy(msg.Answer).([]dnsmessage.RR)
	ttl := c.NormalizeDnsResp(ans)
	if log.IsLevelEnabled(log.TraceLevel) {
		log.WithFields(log.Fields{
			"qname": queryInfo.qname,
			"qtype": queryInfo.qtype,
			"rcode": msg.Rcode,
			"ans":   FormatDnsRsc(ans),
		}).Tracef("Update DNS record cache")
	}
	c.UpdateDnsCacheTtl(cacheKey, queryInfo.qname, ans, ttl)

	return nil
}

func (c *DnsController) Close() error {
	c.dnsForwarderCache.Range(func(key, value any) bool {
		if forwarder, ok := value.(io.Closer); ok {
			forwarder.Close()
		}
		return true
	})
	return nil
}
