// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	dns "github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

// dnsRelay forwards client messages to their routed destination. It has no
// query generator, resolver policy, response cache, retry or transport fallback.
type dnsRelay struct {
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
	active sync.WaitGroup
	slots  chan struct{}
}

func newDNSRelay() *dnsRelay {
	ctx, cancel := context.WithCancel(context.Background())
	return &dnsRelay{ctx: ctx, cancel: cancel, slots: make(chan struct{}, 1024)}
}

var errDNSCapacity = errors.New("DNS request capacity exhausted")

func (r *dnsRelay) admit() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return net.ErrClosed
	}
	select {
	case r.slots <- struct{}{}:
	default:
		return errDNSCapacity
	}
	r.active.Add(1)
	return nil
}

func (r *dnsRelay) finish() { <-r.slots; r.active.Done() }

func (r *dnsRelay) stop() {
	r.mu.Lock()
	r.closed = true
	r.cancel()
	r.mu.Unlock()
}

func (r *dnsRelay) Close() error {
	r.stop()
	r.active.Wait()
	return nil
}

func (c *ControlPlane) dnsRequest(wire []byte, network string, src, dst netip.AddrPort, identity routingResult) (*plugin.DNSExchange, bool, error) {
	proto := consts.L4ProtoStr_TCP
	if network == "udp" {
		proto = consts.L4ProtoStr_UDP
	}
	target, err := c.routingMatcher.matchDestination(&RouteParam{Src: src, Dest: dst, routingResult: &identity,
		networkType: common.NetworkType{L4Proto: proto, IpVersion: consts.IpVersionStrFromAddr(dst.Addr())}})
	if err != nil {
		return nil, false, err
	}
	if !target.IsValid() {
		target = dst
	}
	// Destination capture can hand off before terminal flow controls. Evaluate
	// the selected target before admitting plugins, so a later must still wins.
	bypass := identity.Must != 0
	if identity.CaptureFlags&(captureDestination|captureHTTPRequest) != 0 {
		input := identity.routingInput(src, target, "", proto.ToL4ProtoType())
		input.stage = routeAfterTarget
		outbound, _, must, err := c.routingMatcher.match(input)
		if err != nil {
			return nil, false, err
		}
		if outbound == consts.OutboundBlock {
			return nil, false, errors.New("DNS destination blocked by routing")
		}
		bypass = bypass || must
	}
	request := &plugin.DNSExchange{DNSPacket: plugin.DNSWire(wire), Network: network,
		Source: src, OriginalDestination: dst, Destination: target, Interface: identity.Ifindex}
	request.RouteUpstream = func(ctx context.Context, query *plugin.DNSExchange, upstream plugin.DNSUpstream) (*plugin.DNSExchange, error) {
		option, err := c.dnsUpstreamOption(ctx, upstream.Network, upstream.Address.String(), upstream.Hostname, query, identity)
		if err != nil {
			return nil, err
		}
		query.Egress = c.dnsEgress(option.Outbound, option.Dialer, option.Direct, option.Mark)
		query.DialContext, query.ListenPacket = c.dnsDialers(identity, func(_ context.Context, network, address, hostname string) (*DialOption, error) {
			if network != upstream.Network || address != upstream.Address.String() || hostname != upstream.Hostname {
				return nil, errors.New("DNS transport changed its prepared upstream")
			}
			return option, nil
		})
		return query, nil
	}
	request.DialContext, request.ListenPacket = c.dnsDialers(identity, func(ctx context.Context, network, address, hostname string) (*DialOption, error) {
		return c.dnsUpstreamOption(ctx, network, address, hostname, request, identity)
	})
	return request, bypass, nil
}

// dnsEgress identifies the network position an answer stands for: the
// selected proxy path, or direct traffic with its effective mark. A failover
// or reload that changes the node changes the egress. A group that picks a
// node per connection stands for all its members: its traffic takes any of
// them regardless of the node that carried the query.
func (c *ControlPlane) dnsEgress(group *outbound.DialerGroup, path *dialer.Dialer, direct bool, mark uint32) string {
	if direct {
		if mark == 0 {
			mark = c.soMarkFromDae
		}
		return "direct/" + strconv.FormatUint(uint64(mark), 10)
	}
	if group.SelectsPerConnection() {
		return "proxy/" + group.PathsDigest()
	}
	return "proxy/" + path.LinkDigest()
}

// dnsUpstreamOption routes one DNS dial and selects its node.
func (c *ControlPlane) dnsUpstreamOption(ctx context.Context, network, address, hostname string, request *plugin.DNSExchange, identity routingResult) (*DialOption, error) {
	param, decision, err := c.routingMatcher.dnsRoute(ctx, network, address, hostname, request, identity)
	if err != nil {
		return nil, err
	}
	return c.selectDialOption(ctx, param, decision.outbound, decision.mark, false)
}

// dnsDialers dial the node selected for each dial. Unbound exchanges select
// for every dial; prepared exchanges reuse their upstream selection.
func (c *ControlPlane) dnsDialers(identity routingResult, selectOption func(ctx context.Context, network, address, hostname string) (*DialOption, error)) (
	func(ctx context.Context, network, address, hostname string) (net.Conn, error),
	func(ctx context.Context, address, hostname string) (net.PacketConn, error),
) {
	dial := func(ctx context.Context, network, address, hostname string) (net.Conn, error) {
		option, err := selectOption(ctx, network, address, hostname)
		if err != nil {
			return nil, err
		}
		return c.dialDNSUpstream(ctx, network, option, identity)
	}
	listen := func(ctx context.Context, address, hostname string) (net.PacketConn, error) {
		option, err := selectOption(ctx, "udp", address, hostname)
		if err != nil {
			return nil, err
		}
		return c.listenDNSUpstream(ctx, option, identity)
	}
	return dial, listen
}

func (matcher *RoutingMatcher) dnsRoute(ctx context.Context, network, address, hostname string, request *plugin.DNSExchange, identity routingResult) (*RouteParam, routeDecision, error) {
	if network != "tcp" && network != "udp" {
		return nil, routeDecision{}, fmt.Errorf("unsupported DNS dial network %q", network)
	}
	target, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, routeDecision{}, fmt.Errorf("DNS plugin dial target must be an IP:port: %w", err)
	}
	if target.Port() == 0 || target.Addr().Zone() != "" {
		return nil, routeDecision{}, fmt.Errorf("DNS plugin dial target requires a nonzero port and an unzoned IP")
	}
	if err := ctx.Err(); err != nil {
		return nil, routeDecision{}, err
	}
	if _, err := netip.ParseAddr(hostname); err == nil {
		hostname = ""
	}
	proto := consts.L4ProtoStr_TCP
	if network == "udp" {
		proto = consts.L4ProtoStr_UDP
	}
	param := &RouteParam{Src: request.Source, Dest: target, Domain: hostname, routingResult: &identity, explicitTarget: true,
		networkType: common.NetworkType{L4Proto: proto, IpVersion: consts.IpVersionStrFromAddr(target.Addr())}}
	// Target transformation was performed once at ingress. Preserve the kernel
	// decision only for the unchanged flow; plugin servers get fresh target policy.
	decision, valid := kernelRoute(&identity)
	if !(hostname == "" && target == request.OriginalDestination && request.Destination == request.OriginalDestination && network == request.Network && valid && identity.CaptureFlags&(captureDestination|captureHTTPRequest) == 0) {
		// DNS transports always use the selected IP even when hostname routing
		// and dial_target_override are enabled.
		param.destination = target
		input := param.routingInput(hostname, target).targetInput(hostname, true, nil, nil)
		decision.outbound, decision.mark, decision.must, err = matcher.match(input)
	}
	if err == nil && decision.outbound > consts.OutboundUserDefinedMax {
		err = fmt.Errorf("cannot resolve DNS routing for %s", target)
	}
	if err == nil && decision.outbound == consts.OutboundBlock {
		err = errors.New("DNS destination blocked by routing")
	}
	decision.apply(param.routingResult)
	return param, decision, err
}

func (c *ControlPlane) processDNS(ctx context.Context, request *plugin.DNSExchange, identity routingResult, bypass bool, terminal plugin.DNSHandler, deliver func([]byte) error) error {
	if bypass {
		response, err := terminal(ctx, request)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if response != nil {
			wire, err := response.Wire()
			if err != nil {
				return err
			}
			return deliver(wire)
		}
		return nil
	}
	host := c.MITMHost()
	if host != nil {
		// Auxiliary HTTP always selects its own target using the original DNS
		// client's identity, before looking up a policy-keyed connection pool.
		planner := &httpRoutePlanner{plane: c, network: "tcp", source: request.Source, identity: identity}
		client, closeClient := host.RoutedHTTPClient(planner.plan)
		client.Timeout = consts.DefaultDNSTimeout
		request.Client = client
		defer closeClient()
	}
	_, err := host.HandleDNS(ctx, request, terminal, func(response *plugin.DNSResponse) error {
		query := request.MessageCopy()
		var wire []byte
		var err error
		if response.IsWire() {
			wire, err = response.Wire()
		} else {
			message := response.MessageCopy()
			if message == nil {
				return errors.New("empty DNS response")
			}
			if request.Network == "udp" {
				limit := dns.MinMsgSize
				if query != nil {
					if opt := query.IsEdns0(); opt != nil {
						limit = max(limit, int(opt.UDPSize()))
					}
				}
				message.Truncate(limit)
			}
			wire, err = message.Pack()
		}
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		// Observe exactly the delivered bytes, including local truncation.
		if !response.IsWire() {
			response.DNSPacket = plugin.DNSWire(wire)
		}
		matches := dnsResponseMatches(query, response.MessageCopy())
		if matches {
			now := time.Now()
			if response.ReceivedAt.IsZero() {
				response.ReceivedAt = now
			}
			// The kernel holds the answer's domain evidence before the client
			// can connect to an answered address. A failed delivery keeps it:
			// the answer is genuine, only undelivered.
			if c.core != nil && c.routingMatcher != nil {
				c.observeDNS(request, response, now)
			}
		}
		if err := deliver(wire); err != nil {
			return err
		}
		if matches {
			host.ObserveDNS(ctx, request, response)
		}
		return nil
	})
	return err
}

func (c *ControlPlane) handleDNSUDP(wire []byte, src, dst netip.AddrPort, identity routingResult) {
	r := c.dnsRelay
	if r == nil {
		return
	}
	if err := r.admit(); err != nil {
		if err == errDNSCapacity {
			dropDNSAdmission.Add(1)
		}
		return
	}
	routeLease, err := c.deviceRoutes.acquire(&identity)
	if err != nil {
		r.finish()
		return
	}
	request, bypass, err := c.dnsRequest(wire, "udp", src, dst, identity)
	if err != nil {
		r.finish()
		return
	}
	go func() {
		defer r.finish()
		ctx, cancel := context.WithTimeout(r.ctx, consts.DefaultDNSTimeout)
		defer cancel()
		stopRoute := watchAbort(nil, nil, routeLease, cancel)
		defer stopRoute()
		if routeLease.AbortCause() != nil {
			return
		}
		err := c.processDNS(ctx, request, identity, bypass, relayDNSUDP, func(wire []byte) error {
			if cause := routeLease.AbortCause(); cause != nil {
				return cause
			}
			return sendPktWithMark(wire, dst, src, c.soMarkFromDae)
		})
		if err != nil && ctx.Err() == nil {
			log.WithError(err).WithFields(log.Fields{"source": src, "destination": dst}).Debug("DNS relay failed")
		}
	}()
}

func relayDNSUDP(ctx context.Context, request *plugin.DNSExchange) (*plugin.DNSResponse, error) {
	query, err := request.Wire()
	if err != nil {
		return nil, err
	}
	conn, err := request.DialContext(ctx, "udp", request.Destination.String(), "")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	wire := pool.GetBuffer(consts.MaxDnsMessageSize)
	defer pool.PutBuffer(wire)
	n, err := conn.Read(wire)
	if err != nil {
		return nil, err
	}
	// The response owns only its received bytes, not the pooled receive buffer.
	return &plugin.DNSResponse{DNSPacket: plugin.DNSWire(wire[:n]), ReceivedAt: time.Now(), Origin: "relay"}, nil
}

func (c *ControlPlane) serveDNSTCP(conn net.Conn, src, dst netip.AddrPort, identity routingResult) error {
	r := c.dnsRelay
	if r == nil || r.admit() != nil {
		return net.ErrClosed
	}
	defer r.finish()
	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	routeLease, err := c.deviceRoutes.acquire(&identity)
	if err != nil {
		return err
	}
	stopRoute := watchAbort(nil, nil, routeLease, cancel)
	defer stopRoute()
	// Native/Host DNAT is a connection decision. Reuse the selected target for
	// every message rather than randomly selecting a new address per query.
	template, bypass, err := c.dnsRequest(nil, "tcp", src, dst, identity)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	// Both request and response progress refresh idle time. Once an upstream
	// closes, stop accepting requests and drain admitted response writers before
	// propagating closure to the client. A later write cannot rearm that cutoff.
	var readMu sync.Mutex
	upstreamClosed := false
	refreshRead := func() {
		readMu.Lock()
		defer readMu.Unlock()
		if !upstreamClosed {
			_ = conn.SetReadDeadline(time.Now().Add(2 * consts.DefaultDNSTimeout))
		}
	}
	endRead := func() {
		readMu.Lock()
		defer readMu.Unlock()
		upstreamClosed = true
		_ = conn.SetReadDeadline(time.Now())
	}
	var writeMu, streamsMu sync.Mutex
	write := func(wire []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(consts.DefaultDNSTimeout))
		if err := netutils.WriteDNSFrame(conn, wire); err != nil {
			return err
		}
		refreshRead()
		return nil
	}
	// A retained stream belongs to one egress and resolver address. A group
	// picking nodes per connection keeps the node its stream opened with.
	type streamKey struct {
		egress      string
		destination netip.AddrPort
	}
	streams := make(map[streamKey]*dnsStream)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		streamsMu.Lock()
		for _, stream := range streams {
			_ = stream.conn.Close()
		}
		streamsMu.Unlock()
		workers.Wait()
		for _, stream := range streams {
			stream.close()
		}
	}()
	exchangeOnce := func(operation context.Context, request *plugin.DNSExchange) (*plugin.DNSResponse, error) {
		upstream, err := request.DialContext(operation, "tcp", request.Destination.String(), "")
		if err != nil {
			return nil, err
		}
		stream := newDNSStream(upstream, func([]byte) error { return nil }, func() {})
		defer stream.close()
		return stream.exchange(operation, request)
	}
	terminal := func(operation context.Context, request *plugin.DNSExchange) (*plugin.DNSResponse, error) {
		if request.Independent() {
			return exchangeOnce(operation, request)
		}
		streamsMu.Lock()
		key := streamKey{request.Egress, request.Destination}
		stream := streams[key]
		if stream == nil {
			// Retained streams are bounded; further egresses, e.g. after
			// repeated node switches, exchange on their own connection.
			if len(streams) >= 16 {
				streamsMu.Unlock()
				return exchangeOnce(operation, request)
			}
			upstream, err := request.DialContext(operation, "tcp", request.Destination.String(), "")
			if err != nil {
				streamsMu.Unlock()
				return nil, err
			}
			stream = newDNSStream(upstream, write, endRead)
			streams[key] = stream
		}
		streamsMu.Unlock()
		return stream.exchange(operation, request)
	}
	concurrency := make(chan struct{}, 32)
	refreshRead()
	for {
		wire, err := netutils.ReadDNSFrame(conn)
		if err != nil {
			// Upstream EOF can race finalization of its last correlated response.
			// Each worker already has its own bounded, cancellable deadline.
			workers.Wait()
			readMu.Lock()
			closed := upstreamClosed
			readMu.Unlock()
			if errors.Is(err, io.EOF) || closed {
				return nil
			}
			return err
		}
		refreshRead()
		select {
		case concurrency <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		if r.admit() != nil {
			return errDNSCapacity
		}
		request := template.Copy()
		request.DNSPacket = plugin.DNSWire(wire)
		workers.Go(func() {
			defer r.finish()
			defer func() { <-concurrency }()
			operation, stop := context.WithTimeout(ctx, consts.DefaultDNSTimeout)
			defer stop()
			err := c.processDNS(operation, request, identity, bypass, terminal, write)
			if err != nil {
				cancel()
			}
		})
	}
}
