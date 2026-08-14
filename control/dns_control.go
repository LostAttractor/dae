/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strings"
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
	SoMarkFromDae     uint32
}

type DnsController struct {
	routing     *dns.Dns
	qtypePrefer uint16

	matchBitmap       func(fqdn string) []uint32
	registry          *DomainRegistry
	bestDialerChooser func(req *udpRequest, upstream *dns.Upstream) (*dialArgument, error)

	fixedDomainTtl    map[string]int
	dnsCache          *commonDnsCache
	dnsForwarderCache map[dnsForwarderKey]DnsForwarder

	dnsFlightMu sync.Mutex
	dnsFlights  map[dnsFlightKey]*dnsFlight
	// Set per controller so timeout behavior can be tested without mutating
	// process-wide state.
	dnsDuplicateWaitTimeout time.Duration

	// lifecycleMu linearizes shutdown with flight/forwarder creation and
	// publication. Forwarder and response I/O run outside this mutex; admitted
	// requests keep Close from returning until their final send completes.
	lifecycleMu    sync.Mutex
	closeOnce      sync.Once
	closeErr       error
	activeRequests sync.WaitGroup
	sendPacket     func([]byte, netip.AddrPort, netip.AddrPort) error
	// closed is canceled by Close: once closed, the controller must not serve
	// new requests — its forwarders are closed, and its writes would land on
	// the shared eBPF maps the next control plane owns.
	closed context.Context
	close  context.CancelFunc

	cacheSweeperDone chan struct{}
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
	c = &DnsController{
		routing:     routing,
		qtypePrefer: prefer,

		matchBitmap:       option.MatchBitmap,
		registry:          option.DomainRegistry,
		bestDialerChooser: option.BestDialerChooser,

		fixedDomainTtl:          option.FixedDomainTtl,
		dnsForwarderCache:       make(map[dnsForwarderKey]DnsForwarder),
		dnsCache:                newCommonDnsCache(32768),
		dnsFlights:              make(map[dnsFlightKey]*dnsFlight),
		dnsDuplicateWaitTimeout: consts.DnsDuplicateWaitTimeout,
		sendPacket: func(data []byte, from, to netip.AddrPort) error {
			return sendPktWithMark(data, from, to, option.SoMarkFromDae)
		},
		closed:           closed,
		close:            close,
		cacheSweeperDone: make(chan struct{}),
	}
	go c.runDnsCacheSweeper()
	return c, nil
}

func (c *DnsController) runDnsCacheSweeper() {
	defer close(c.cacheSweeperDone)
	ticker := time.NewTicker(consts.DnsStateSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.closed.Done():
			return
		case now := <-ticker.C:
			c.dnsCache.sweep(now)
		}
	}
}

func (c *DnsController) applyFixedTTL(fqdn string, answers []dnsmessage.RR) {
	fixedTTL, ok := c.fixedDomainTtl[fqdn]
	if !ok {
		return
	}
	ttl := dnsTTLToUint32(fixedTTL)
	for _, answer := range answers {
		answer.Header().Ttl = ttl
	}
}

func (c *DnsController) applyResponsePlanTTL(fqdn string, answers []dnsmessage.RR, plan *responsePlan) {
	if plan == nil || len(plan.views) == 0 {
		c.applyFixedTTL(fqdn, answers)
		return
	}
	ttlByAnswer := make(map[dnsAnswerKey]int, len(plan.views[0].answers))
	now := time.Now()
	for _, answer := range plan.views[0].answers {
		remainingSeconds := max(0, int((answer.absoluteDeadline.Sub(now)+time.Second-1)/time.Second))
		ttlByAnswer[dnsAnswerIdentity(answer.rr)] = remainingSeconds
	}
	for _, answer := range answers {
		if ttl, exists := ttlByAnswer[dnsAnswerIdentity(answer)]; exists {
			answer.Header().Ttl = dnsTTLToUint32(ttl)
		}
	}
}

func dnsTTLToUint32(ttl int) uint32 {
	if ttl <= 0 {
		return 0
	}
	if uint64(ttl) > uint64(math.MaxInt32) {
		return math.MaxInt32
	}
	return uint32(ttl)
}

func (c *DnsController) cacheResponsePlan(cacheKey dnsCacheKey, plan *responsePlan) {
	if plan == nil {
		return
	}
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.closed.Err() != nil {
		return
	}
	c.cacheResponsePlanOpen(cacheKey, plan)
}

// cacheResponsePlanOpen requires lifecycleMu to be held and the controller to
// be open.
func (c *DnsController) cacheResponsePlanOpen(cacheKey dnsCacheKey, plan *responsePlan) {
	if !plan.cacheEligible {
		return
	}
	for _, view := range plan.views {
		c.cacheResponseView(cacheKey, plan.observedAt, view)
	}
}

func (c *DnsController) cacheResponseView(cacheKey dnsCacheKey, observedAt time.Time, view responseView) {
	values := make([]*DnsCache, 0, len(view.answers))
	for _, answer := range view.answers {
		if answer.absoluteDeadline.After(observedAt) {
			values = append(values, newDnsCache(answer.rr, answer.absoluteDeadline))
		}
	}
	validUntil := view.validUntil
	if !validUntil.IsZero() && !validUntil.After(observedAt) {
		values = nil
	}
	cacheKey.queryInfo = view.query
	c.dnsCache.Replace(cacheKey, values, validUntil)
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"qname":    view.query.qname,
			"qtype":    view.query.qtype,
			"upstream": cacheKey.upstream,
			"answers":  len(view.answers),
		}).Debug("Update DNS record cache")
	}
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
	upstream    string
	networkType common.NetworkType
	dialer      *dialer.Dialer
	target      netip.AddrPort
}

type queryInfo struct {
	qname string
	qtype uint16
}

type dnsQueryKey struct {
	queryInfo
	qclass uint16
	// variant is a canonical representation of all response-varying request
	// data other than qname/qtype/qclass.
	variant string
}

type dnsCacheKey struct {
	queryInfo
	variant string
	dnsForwarderKey
}

type pendingDNSResponse struct {
	cacheKey   dnsCacheKey
	register   bool
	cacheable  bool
	receivedAt time.Time
}

// A flight covers response rerouting as well as the initial exchange. Include
// the complete request routing context because choosing a later upstream's
// dialer can produce a different result even when the first hop was identical.
type dnsFlightKey struct {
	query         dnsQueryKey
	upstreamIndex consts.DnsRequestOutboundIndex
	forwarder     dnsForwarderKey
	route         dnsRerouteKey
}

type dnsRerouteKey struct {
	src     netip.AddrPort
	pname   [16]uint8
	ifindex uint32
	dscp    uint8
	mac     [6]uint8
}

type dnsFlight struct {
	done             chan struct{}
	participantCount int
	result           *dnsmessage.Msg
	err              error
}

func newDNSFlight() *dnsFlight {
	return &dnsFlight{done: make(chan struct{}), participantCount: 1}
}

func (f *dnsFlight) complete(msg *dnsmessage.Msg, err error) {
	if err == nil && msg != nil {
		f.result = msg.Copy()
	}
	f.err = err
	close(f.done)
}

func (c *DnsController) prepareQueryInfo(dnsMessage *dnsmessage.Msg) (queryInfo queryInfo) {
	q := dnsMessage.Question[0]
	queryInfo.qname = dnsmessage.CanonicalName(q.Name)
	queryInfo.qtype = q.Qtype
	return
}

func makeDNSQueryKey(msg *dnsmessage.Msg, queryInfo queryInfo) (dnsQueryKey, bool, bool) {
	variant, flightOK := dnsQueryVariant(msg)
	var qclass uint16
	if msg != nil && len(msg.Question) == 1 {
		qclass = msg.Question[0].Qclass
	}
	return dnsQueryKey{
		queryInfo: queryInfo,
		qclass:    qclass,
		variant:   variant,
	}, flightOK, flightOK && dnsQueryCacheable(msg)
}

func makeDNSForwarderKey(upstream *dns.Upstream, argument *dialArgument) dnsForwarderKey {
	return dnsForwarderKey{
		upstream:    upstream.String(),
		networkType: argument.networkType,
		dialer:      argument.Dialer,
		target:      argument.Target,
	}
}

func makeDNSCacheKey(query dnsQueryKey, forwarder dnsForwarderKey) dnsCacheKey {
	return dnsCacheKey{
		queryInfo:       query.queryInfo,
		variant:         query.variant,
		dnsForwarderKey: forwarder,
	}
}

func makeDNSRerouteKey(req *udpRequest) dnsRerouteKey {
	key := dnsRerouteKey{src: req.src}
	if req.routingResult != nil {
		key.pname = req.routingResult.Pname
		key.ifindex = req.routingResult.Ifindex
		key.dscp = req.routingResult.Dscp
		key.mac = req.routingResult.Mac
	}
	return key
}

func (c *DnsController) sendDNSPacket(data []byte, from, to netip.AddrPort) error {
	if c.closed.Err() != nil {
		return net.ErrClosed
	}
	return c.sendPacket(data, from, to)
}

func (c *DnsController) admitDNSRequest() bool {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.closed.Err() != nil {
		return false
	}
	c.activeRequests.Add(1)
	return true
}

func (c *DnsController) Handle(dnsMessage *dnsmessage.Msg, req *udpRequest) (err error) {
	if c.closed.Err() != nil || dnsMessage == nil || req == nil {
		return nil
	}
	if dnsMessage.Response {
		return nil
	}

	id := dnsMessage.Id
	question := append([]dnsmessage.Question(nil), dnsMessage.Question...)
	udpPayloadSize := dnsUDPPayloadSize(dnsMessage)
	if !c.admitDNSRequest() {
		// Drop requests arriving while the owning plane is being retired.
		return nil
	}
	if len(dnsMessage.Question) != 1 {
		go func() {
			defer c.activeRequests.Done()
			response := new(dnsmessage.Msg)
			response.SetRcode(dnsMessage, dnsmessage.RcodeFormatError)
			*dnsMessage = *response
			c.writeDNSResponse(dnsMessage, req, id, nil, udpPayloadSize)
		}()
		return nil
	}
	queryInfo := c.prepareQueryInfo(dnsMessage)
	if log.IsLevelEnabled(log.TraceLevel) {
		log.Tracef("Received UDP(DNS) %v <-> %v: %v %v",
			RefineSourceToShow(req.src, req.dst.Addr()), req.dst.String(), queryInfo.qname, queryInfo.qtype,
		)
	}

	go func() {
		defer c.activeRequests.Done()
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
				errCh <- c.handleDNSRequest(c.closed, dnsMessage2, req, queryInfo2)
			}()
			err = oops.Join(c.handleDNSRequest(c.closed, dnsMessage, req, queryInfo), <-errCh)
			if err != nil {
				goto err
			}
			if c.qtypePrefer != queryInfo.qtype && dnsMessage2 != nil && IncludeAnyIpInMsg(dnsMessage2) {
				c.reject(dnsMessage)
			}
		} else {
			err = c.handleDNSRequest(c.closed, dnsMessage, req, queryInfo)
		}
	err:
		if err != nil {
			if errors.Is(err, net.ErrClosed) ||
				(c.closed.Err() != nil && errors.Is(err, context.Canceled)) {
				return
			}
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
		c.writeDNSResponse(dnsMessage, req, id, question, udpPayloadSize)
	}()

	return nil
}

func dnsUDPPayloadSize(msg *dnsmessage.Msg) int {
	if opt := msg.IsEdns0(); opt != nil {
		return max(dnsmessage.MinMsgSize, min(int(opt.UDPSize()), dnsmessage.MaxMsgSize))
	}
	return dnsmessage.MinMsgSize
}

func (c *DnsController) writeDNSResponse(msg *dnsmessage.Msg, req *udpRequest, id uint16, question []dnsmessage.Question, udpPayloadSize int) {
	msg.Id = id
	msg.Question = append([]dnsmessage.Question(nil), question...)
	msg.Truncate(udpPayloadSize)
	msg.Compress = true
	data, err := msg.Pack()
	if err != nil {
		log.Errorf("%+v", oops.Wrapf(err, "failed to pack dns message"))
		return
	}
	if err = c.sendDNSPacket(data, req.dst, req.src); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Warningf("%+v", oops.Wrapf(err, "failed to send dns message back"))
	}
}

// TODO: 除了dialSend, 不应该有可预期的 err
// TODO: qname=. qtype=2 的查询是什么, 为什么没有缓存, 因为AsIs?
// TODO: 如果AsIs都不缓存的话，如果一个server可用一个不可用，那就是远端sever的问题?
func (c *DnsController) handleDNSRequest(
	ctx context.Context,
	dnsMessage *dnsmessage.Msg,
	req *udpRequest,
	queryInfo queryInfo,
) (err error) {
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
		upstream, err = c.routing.GetUpstream(ctx, RequestIndex)
		if err != nil {
			return err
		}
	}
	cacheForwarder := RequestIndex != consts.DnsRequestOutboundIndex_AsIs

	firstDialArgument, err := c.bestDialerChooser(req, upstream)
	if err != nil {
		return err
	}
	queryKey, canShare, cacheable := makeDNSQueryKey(dnsMessage, queryInfo)
	forwarderKey := makeDNSForwarderKey(upstream, firstDialArgument)
	flightKey := dnsFlightKey{
		query: queryKey, upstreamIndex: RequestIndex,
		forwarder: forwarderKey, route: makeDNSRerouteKey(req),
	}
	resolve := func() error {
		return c.resolveDNSRequest(ctx, dnsMessage, req, queryKey, cacheable, RequestIndex, upstream, firstDialArgument, cacheForwarder)
	}
	if canShare {
		return c.shareDNSResult(ctx, flightKey, dnsMessage, resolve)
	}
	err = resolve()
	if err == nil && c.closed.Err() != nil {
		return net.ErrClosed
	}
	return err
}

// resolveDNSRequest performs response routing and publication for the leader
// of a request flight. Followers receive only its final message or error.
func (c *DnsController) resolveDNSRequest(
	ctx context.Context,
	dnsMessage *dnsmessage.Msg,
	req *udpRequest,
	queryKey dnsQueryKey,
	queryCacheable bool,
	upstreamIndex consts.DnsRequestOutboundIndex,
	upstream *dns.Upstream,
	dialArgument *dialArgument,
	cacheForwarder bool,
) error {
	queryInfo := queryKey.queryInfo
	reqMsg := dnsMessage.Copy()
	var pending *pendingDNSResponse
	var err error
Dial:
	for invokingDepth := 1; invokingDepth <= consts.MaxDnsLookupDepth; invokingDepth++ {
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"question": dnsMessage.Question,
				"upstream": upstream.String(),
			}).Debugln("Request to DNS upstream")
		}

		if dialArgument == nil {
			dialArgument, err = c.bestDialerChooser(req, upstream)
			if err != nil {
				return err
			}
		}

		// TODO: 这里可能不可以这样做
		pending, err = c.dialSend(ctx, dnsMessage, upstream, dialArgument, queryKey, queryCacheable, cacheForwarder)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return err
			}
			netErr, ok := IsNetError(err)
			err = oops.
				In("DialContext").
				With("Is NetError", ok).
				With("Is Temporary", ok && netErr.Temporary()).
				With("Is Timeout", ok && netErr.Timeout()).
				Wrapf(err, "DNS dialSend error")
			if ok && !netErr.Timeout() && dialArgument.Dialer.NeedAliveState() {
				labels := prometheus.Labels{
					"id":       dialArgument.Dialer.StatsID(),
					"outbound": dialArgument.Outbound.Name,
					"subtag":   dialArgument.Dialer.Property.SubscriptionTag,
					"dialer":   dialArgument.Dialer.Name,
					"network":  dialArgument.networkType.String(),
				}
				common.ErrorCount.With(labels).Inc()
				dialArgument.Dialer.ReportUnavailable()
			}
			return err
		}

		ResponseIndex, err := c.routing.ResponseSelect(dnsMessage, upstreamIndex)
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
		if invokingDepth == consts.MaxDnsLookupDepth {
			return oops.Errorf("too deep DNS lookup invoking (depth: %v); there may be infinite loop in your DNS response routing", consts.MaxDnsLookupDepth)
		}
		nextUpstreamIndex := consts.DnsRequestOutboundIndex(ResponseIndex)
		nextUpstream, err := c.routing.GetUpstream(ctx, nextUpstreamIndex)
		if err != nil {
			return err
		}
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"question":      dnsMessage.Question,
				"last_upstream": upstream.String(),
				"next_upstream": nextUpstream.String(),
			}).Debugln("Change DNS upstream and resend")
		}
		pending = nil
		upstreamIndex = nextUpstreamIndex
		upstream = nextUpstream
		cacheForwarder = true
		dialArgument = nil
		*dnsMessage = *reqMsg.Copy()
	}
	// TODO: dial_mode: domain 的逻辑失效问题
	c.finalizeAcceptedResponse(dnsMessage, pending)
	return nil
}

// shareDNSResult coalesces the complete response-routing operation, not just
// the upstream exchange. This lets every concurrent identical request receive
// the leader's final response even when that response cannot enter the cache.
func (c *DnsController) shareDNSResult(ctx context.Context, flightKey dnsFlightKey, msg *dnsmessage.Msg, resolve func() error) (err error) {
	flight, leader, err := c.joinDNSFlight(flightKey)
	if err != nil {
		return err
	}
	if flight == nil {
		if log.IsLevelEnabled(log.DebugLevel) {
			log.Debugf("UDP(DNS) <-> Drop excess duplicate lookup: %v %v", flightKey.query.qname, flightKey.query.qtype)
		}
		return nil
	}
	if !leader {
		return c.waitDNSFlight(ctx, flightKey, flight, msg)
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			c.finishDNSFlight(flightKey, flight, nil, fmt.Errorf("DNS flight panicked: %v", recovered))
			panic(recovered)
		}
		c.finishDNSFlight(flightKey, flight, msg, err)
	}()

	err = resolve()
	if err == nil && c.closed.Err() != nil {
		err = net.ErrClosed
	}
	return err
}

// joinDNSFlight returns a nil flight without an error when an existing flight
// has reached its participant limit.
func (c *DnsController) joinDNSFlight(flightKey dnsFlightKey) (*dnsFlight, bool, error) {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.closed.Err() != nil {
		return nil, false, net.ErrClosed
	}

	c.dnsFlightMu.Lock()
	defer c.dnsFlightMu.Unlock()
	if flight := c.dnsFlights[flightKey]; flight != nil {
		if flight.participantCount >= consts.MaxDnsFlightParticipants {
			return nil, false, nil
		}
		flight.participantCount++
		return flight, false, nil
	}
	flight := newDNSFlight()
	c.dnsFlights[flightKey] = flight
	return flight, true, nil
}

func (c *DnsController) waitDNSFlight(ctx context.Context, flightKey dnsFlightKey, flight *dnsFlight, msg *dnsmessage.Msg) error {
	waitCtx, cancel := context.WithTimeout(ctx, c.dnsDuplicateWaitTimeout)
	defer cancel()
	select {
	case <-flight.done:
	case <-waitCtx.Done():
		if !c.leaveDNSFlight(flightKey, flight) {
			// Completion won under dnsFlightMu, so done is already closed and its
			// result should take precedence over the simultaneous timeout.
			<-flight.done
			return c.applyDNSFlightResult(flight, msg)
		}
		if c.closed.Err() != nil {
			return net.ErrClosed
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if log.IsLevelEnabled(log.DebugLevel) {
			log.Debugf("UDP(DNS) <-> Drop stale duplicate lookup: %v %v", flightKey.query.qname, flightKey.query.qtype)
		}
		return nil
	}
	return c.applyDNSFlightResult(flight, msg)
}

func (c *DnsController) applyDNSFlightResult(flight *dnsFlight, msg *dnsmessage.Msg) error {
	if c.closed.Err() != nil {
		return net.ErrClosed
	}
	if flight.result != nil {
		id := msg.Id
		question := append([]dnsmessage.Question(nil), msg.Question...)
		result := flight.result.Copy()
		result.Id = id
		result.Question = question
		*msg = *result
	}
	if c.closed.Err() != nil {
		return net.ErrClosed
	}
	return flight.err
}

// leaveDNSFlight reports whether the flight was still active and the caller's
// participant slot was released. A false result means completion already won.
func (c *DnsController) leaveDNSFlight(flightKey dnsFlightKey, flight *dnsFlight) bool {
	c.dnsFlightMu.Lock()
	defer c.dnsFlightMu.Unlock()
	if c.dnsFlights[flightKey] != flight {
		return false
	}
	flight.participantCount--
	return true
}

func (c *DnsController) finishDNSFlight(flightKey dnsFlightKey, flight *dnsFlight, msg *dnsmessage.Msg, err error) {
	c.dnsFlightMu.Lock()
	defer c.dnsFlightMu.Unlock()
	if c.dnsFlights[flightKey] != flight {
		return
	}
	delete(c.dnsFlights, flightKey)
	flight.complete(msg, err)
}

// finalizeAcceptedResponse clears unauthenticated AD assertions and commits
// routing evidence only after response routing accepts a fresh healthy answer.
// Cache hits have no pending work.
func (c *DnsController) finalizeAcceptedResponse(msg *dnsmessage.Msg, pending *pendingDNSResponse) {
	msg.AuthenticatedData = false
	if pending == nil ||
		!msg.Response ||
		len(msg.Answer) == 0 ||
		len(msg.Question) == 0 ||
		msg.Rcode != dnsmessage.RcodeSuccess ||
		msg.Truncated {
		return
	}
	c.commitAcceptedResponse(msg, pending, pending.receivedAt)
}

func (c *DnsController) commitAcceptedResponse(msg *dnsmessage.Msg, pending *pendingDNSResponse, acceptedAt time.Time) {
	if !pending.register {
		return
	}
	plan := c.planDNSResponseAt(pending.cacheKey.queryInfo, msg.Answer, acceptedAt)
	if plan == nil {
		c.applyResponsePlanTTL(pending.cacheKey.qname, msg.Answer, nil)
		return
	}
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.closed.Err() != nil {
		return
	}
	c.registerResponsePlanOpen(plan, time.Now())
	if pending.cacheable && plan.cacheEligible && !msg.Authoritative && msg.RecursionAvailable {
		c.cacheResponsePlanOpen(pending.cacheKey, plan)
	}
	c.applyResponsePlanTTL(pending.cacheKey.qname, msg.Answer, plan)
}

// registerAddressNoExpiry keeps a DNS-upstream address registered for the
// lifetime of the control plane.
func (c *DnsController) registerAddressNoExpiry(queryInfo queryInfo, ip netip.Addr) {
	if !ip.IsValid() || ip.IsUnspecified() {
		return
	}
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.closed.Err() != nil {
		// Do not write the shared eBPF maps after Close; the next control
		// plane owns them now.
		return
	}
	queryInfo.qname = dnsmessage.CanonicalName(queryInfo.qname)
	domainBitmap := c.matchBitmap(queryInfo.qname)
	c.registry.UpsertNoExpiry(queryInfo, ip, domainBitmap, time.Now())
}

func (c *DnsController) registerResponsePlan(plan *responsePlan, evaluatedAt time.Time) {
	if plan == nil {
		return
	}
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.closed.Err() != nil {
		return
	}
	c.registerResponsePlanOpen(plan, evaluatedAt)
}

// registerResponsePlanOpen requires lifecycleMu to be held and the controller
// to be open.
func (c *DnsController) registerResponsePlanOpen(plan *responsePlan, evaluatedAt time.Time) {
	for _, view := range plan.views {
		if len(view.addresses) == 0 {
			continue
		}
		domainBitmap := c.matchBitmap(view.query.qname)
		for _, address := range view.addresses {
			if view.addressExactLease {
				c.registry.UpsertWithDeadline(view.query, address, domainBitmap, view.addressDeadline, evaluatedAt)
				continue
			}
			c.registry.UpsertObserved(
				view.query, address, domainBitmap,
				deadlineSeconds(view.addressDeadline, plan.observedAt),
				plan.observedAt, evaluatedAt,
			)
		}
	}
}

func dnsAnswerAddress(qtype uint16, answer dnsmessage.RR) (netip.Addr, bool) {
	if answer == nil || answer.Header().Class != dnsmessage.ClassINET {
		return netip.Addr{}, false
	}
	var ip netip.Addr
	var ok bool
	switch body := answer.(type) {
	case *dnsmessage.A:
		if qtype == dnsmessage.TypeA {
			ip, ok = netip.AddrFromSlice(body.A)
		}
	case *dnsmessage.AAAA:
		if qtype == dnsmessage.TypeAAAA {
			ip, ok = netip.AddrFromSlice(body.AAAA)
		}
	}
	return ip, ok && !ip.IsUnspecified()
}

func (c *DnsController) reject(msg *dnsmessage.Msg) {
	msg.Answer = []dnsmessage.RR{}
	msg.Rcode = dnsmessage.RcodeSuccess
	msg.Response = true
	msg.RecursionAvailable = true
	msg.Truncated = false
	msg.AuthenticatedData = false
}

func closeDnsForwarder(forwarder DnsForwarder) error {
	return forwarder.Close()
}

func (c *DnsController) selectDnsForwarder(key dnsForwarderKey, candidate DnsForwarder, cache bool) (DnsForwarder, func()) {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.closed.Err() != nil {
		_ = closeDnsForwarder(candidate)
		return nil, func() {}
	}
	if !cache {
		return candidate, func() { _ = closeDnsForwarder(candidate) }
	}
	if actual := c.dnsForwarderCache[key]; actual != nil {
		_ = closeDnsForwarder(candidate)
		return actual, func() {}
	}
	c.dnsForwarderCache[key] = candidate
	return candidate, func() {}
}

func (c *DnsController) dialSend(
	ctx context.Context,
	msg *dnsmessage.Msg,
	upstream *dns.Upstream,
	dialArgument *dialArgument,
	queryKey dnsQueryKey,
	queryCacheable bool,
	cacheForwarder bool,
) (*pendingDNSResponse, error) {
	queryInfo := queryKey.queryInfo
	request := msg.Copy()
	forwarderKey := makeDNSForwarderKey(upstream, dialArgument)
	cacheKey := makeDNSCacheKey(queryKey, forwarderKey)
	if queryCacheable {
		fromCache, err := c.fillDNSCache(cacheKey, msg)
		if err != nil {
			return nil, err
		}
		if fromCache {
			if log.IsLevelEnabled(log.DebugLevel) && len(msg.Question) > 0 {
				log.WithFields(log.Fields{
					"qname":  queryInfo.qname,
					"qtype":  queryInfo.qtype,
					"rcode":  msg.Rcode,
					"answer": FormatDnsRsc(msg.Answer),
				}).Debugf("UDP(DNS) <-> Cache")
			}
			return nil, nil
		}
	}

	forwarder, releaseForwarder, err := c.getDNSForwarder(forwarderKey, upstream, *dialArgument, cacheForwarder)
	if err != nil {
		return nil, err
	}
	defer releaseForwarder()

	if err = forwarder.ForwardDNS(ctx, msg); err != nil {
		return nil, err
	}
	receivedAt := time.Now()
	if err = validateDNSResponseIdentity(request, msg); err != nil {
		return nil, err
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

	// These responses are deliberately not cached, but the surrounding flight
	// still fans them out to all concurrent identical requests.
	switch {
	case !msg.Response,
		len(msg.Question) == 0,               // Check healthy resp.
		msg.Rcode != dnsmessage.RcodeSuccess, // Check suc resp.
		// A truncated response carries a partial answer; caching it would
		// serve the incomplete RRset with the TC bit cleared (FillInto
		// forces Truncated=false) and short-circuit the client's TCP
		// fallback until the TTL expires. Pass it through uncached.
		msg.Truncated:
		log.WithFields(log.Fields{
			"qname":  queryInfo.qname,
			"qtype":  queryInfo.qtype,
			"rcode":  msg.Rcode,
			"answer": FormatDnsRsc(msg.Answer),
		}).Tracef("Not a valid DNS response")
	}

	return &pendingDNSResponse{
		cacheKey: cacheKey, register: queryKey.qclass == dnsmessage.ClassINET,
		cacheable: queryCacheable, receivedAt: receivedAt,
	}, nil
}

func validateDNSResponseIdentity(request, response *dnsmessage.Msg) error {
	if request == nil || response == nil || !response.Response {
		return oops.Errorf("DNS response expected")
	}
	if response.Id != request.Id || response.Opcode != request.Opcode {
		return oops.Errorf("DNS response identity mismatch")
	}
	if len(request.Question) != 1 || len(response.Question) != 1 {
		return oops.Errorf("DNS response question count mismatch")
	}
	want, got := request.Question[0], response.Question[0]
	if !strings.EqualFold(got.Name, want.Name) || got.Qtype != want.Qtype || got.Qclass != want.Qclass {
		return oops.Errorf("DNS response question mismatch: got %v, want %v", got, want)
	}
	return nil
}

func (c *DnsController) fillDNSCache(cacheKey dnsCacheKey, msg *dnsmessage.Msg) (bool, error) {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.closed.Err() != nil {
		return false, net.ErrClosed
	}
	return c.dnsCache.FillInto(cacheKey, msg), nil
}

func (c *DnsController) getDNSForwarder(key dnsForwarderKey, upstream *dns.Upstream, dialArgument dialArgument, cache bool) (DnsForwarder, func(), error) {
	c.lifecycleMu.Lock()
	if c.closed.Err() != nil {
		c.lifecycleMu.Unlock()
		return nil, func() {}, net.ErrClosed
	}
	if cache {
		if forwarder := c.dnsForwarderCache[key]; forwarder != nil {
			c.lifecycleMu.Unlock()
			return forwarder, func() {}, nil
		}
	}
	c.lifecycleMu.Unlock()

	forwarder, err := newDnsForwarder(c.closed, upstream, dialArgument)
	if err != nil {
		return nil, func() {}, err
	}
	selected, release := c.selectDnsForwarder(key, forwarder, cache)
	if selected == nil {
		return nil, func() {}, net.ErrClosed
	}
	return selected, release, nil
}

func (c *DnsController) Close() error {
	c.closeOnce.Do(func() {
		var forwarders []DnsForwarder

		c.lifecycleMu.Lock()
		c.close()

		c.dnsFlightMu.Lock()
		for key, flight := range c.dnsFlights {
			delete(c.dnsFlights, key)
			flight.complete(nil, net.ErrClosed)
		}
		c.dnsFlightMu.Unlock()

		for _, forwarder := range c.dnsForwarderCache {
			forwarders = append(forwarders, forwarder)
		}
		c.lifecycleMu.Unlock()

		<-c.cacheSweeperDone
		closeResults := make(chan error, len(forwarders))
		for _, forwarder := range forwarders {
			go func(forwarder DnsForwarder) { closeResults <- closeDnsForwarder(forwarder) }(forwarder)
		}
		// Cancellation handles cooperative forwarders; concurrent Close is the
		// fallback for implementations that need their connection interrupted.
		c.activeRequests.Wait()
		timer := time.NewTimer(consts.DefaultDialTimeout)
		defer timer.Stop()
		for range forwarders {
			select {
			case err := <-closeResults:
				c.closeErr = errors.Join(c.closeErr, err)
			case <-timer.C:
				c.closeErr = errors.Join(c.closeErr, fmt.Errorf("DNS forwarder close timeout: %w", context.DeadlineExceeded))
				return
			}
		}
	})
	return c.closeErr
}
