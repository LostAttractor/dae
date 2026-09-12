// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/outbound/pool"
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

func (r *dnsRelay) admit() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	select {
	case r.slots <- struct{}{}:
	default:
		return false
	}
	r.active.Add(1)
	return true
}

func (r *dnsRelay) finish() { <-r.slots; r.active.Done() }

func (r *dnsRelay) Close() error {
	r.mu.Lock()
	r.closed = true
	r.cancel()
	r.mu.Unlock()
	r.active.Wait()
	return nil
}

func (c *ControlPlane) dnsRequest(wire []byte, network string, src, dst netip.AddrPort, identity bpfRoutingResult) (*plugin.DNSRequest, bool, error) {
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
	request := &plugin.DNSRequest{Wire: append([]byte(nil), wire...), Network: network,
		Source: src, OriginalDestination: dst, Destination: target, Interface: identity.Ifindex,
		ContextKey: fmt.Sprintf("%s/%s/%+v", src, dst, identity)}
	if message := unpackDNSMessage(wire); message != nil && !message.Response {
		request.Message = message
	}
	request.DialContext = func(ctx context.Context, network, address, hostname string) (net.Conn, error) {
		option, err := c.dnsDialOption(ctx, network, address, hostname, request, identity)
		if err != nil {
			return nil, err
		}
		return c.dialDNSUpstream(ctx, network, option, identity)
	}
	request.ListenPacket = func(ctx context.Context, address, hostname string) (net.PacketConn, error) {
		option, err := c.dnsDialOption(ctx, "udp", address, hostname, request, identity)
		if err != nil {
			return nil, err
		}
		return c.listenDNSUpstream(ctx, option, identity)
	}
	return request, bypass, nil
}

func (c *ControlPlane) dnsDialOption(ctx context.Context, network, address, hostname string, request *plugin.DNSRequest, identity bpfRoutingResult) (*DialOption, error) {
	if network != "tcp" && network != "udp" {
		return nil, fmt.Errorf("unsupported DNS dial network %q", network)
	}
	target, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, fmt.Errorf("DNS plugin dial target must be an IP:port: %w", err)
	}
	if target.Port() == 0 || target.Addr().Zone() != "" {
		return nil, fmt.Errorf("DNS plugin dial target requires a nonzero port and an unzoned IP")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
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
	var option *DialOption
	// Target transformation was performed once at ingress. Preserve the kernel
	// decision only for the unchanged flow; plugin servers get fresh target policy.
	decision, valid := kernelRoute(&identity)
	if hostname == "" && target == request.OriginalDestination && request.Destination == request.OriginalDestination && network == request.Network && valid && identity.CaptureFlags&(captureDestination|captureHTTPRequest) == 0 {
		option, err = c.selectDialOption(param, decision.outbound, decision.mark, false)
	} else {
		// DNS transports always use the selected IP even when hostname routing
		// and dial_target_override are enabled.
		param.destination = target
		option, err = c.routeDestination(param, hostname)
	}
	if err == nil && option.Outbound.Name == consts.OutboundBlock.String() {
		err = errors.New("DNS destination blocked by routing")
	}
	return option, err
}

func (c *ControlPlane) processDNS(ctx context.Context, request *plugin.DNSRequest, identity bpfRoutingResult, bypass bool, terminal plugin.DNSHandler, deliver func([]byte) error) error {
	if bypass {
		response, err := terminal(ctx, request)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if response != nil {
			return deliver(response.Wire)
		}
		return nil
	}
	if c.mitmHost != nil {
		// Auxiliary HTTP always selects its own target using the original DNS
		// client's identity, before looking up a policy-keyed connection pool.
		planner := &httpRoutePlanner{plane: c, network: "tcp", source: request.Source, identity: identity}
		client, closeClient := c.mitmHost.RoutedHTTPClient(planner.plan)
		client.Timeout = consts.DefaultDNSTimeout
		request.Client = client
		defer closeClient()
	}
	_, err := c.mitmHost.HandleDNS(ctx, request, terminal, func(response *plugin.DNSResponse) error {
		var err error
		if len(response.Wire) == 0 && response.Message != nil {
			message := response.Message.Copy()
			if request.Network == "udp" {
				limit := dns.MinMsgSize
				if request.Message != nil {
					if opt := request.Message.IsEdns0(); opt != nil {
						limit = max(limit, int(opt.UDPSize()))
					}
				}
				message.Truncate(limit)
			}
			response.Wire, err = message.Pack()
			if err != nil {
				return err
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := deliver(response.Wire); err != nil {
			return err
		}
		deliveredAt := time.Now()
		// Publish only successfully delivered bytes, including local truncation.
		message := unpackDNSMessage(response.Wire)
		if dnsResponseMatches(request.Message, message) {
			response.Message = message
			if response.ReceivedAt.IsZero() {
				response.ReceivedAt = deliveredAt
			}
			if c.core != nil && c.routingMatcher != nil {
				observeDNSRegistryAt(c.core.domainRegistry, c.routingMatcher.domainMatcher.MatchDomainBitmap, request, response, deliveredAt)
			}
			c.mitmHost.ObserveDNS(ctx, request, response)
		}
		return nil
	})
	return err
}

func (c *ControlPlane) handleDNSUDP(wire []byte, src, dst netip.AddrPort, identity bpfRoutingResult) {
	r := c.dnsRelay
	if r == nil || !r.admit() {
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

func relayDNSUDP(ctx context.Context, request *plugin.DNSRequest) (*plugin.DNSResponse, error) {
	conn, err := request.DialContext(ctx, "udp", request.Destination.String(), "")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if _, err := conn.Write(request.Wire); err != nil {
		return nil, err
	}
	wire := pool.GetBuffer(consts.MaxDnsMessageSize)
	defer pool.PutBuffer(wire)
	n, err := conn.Read(wire)
	if err != nil {
		return nil, err
	}
	// The response owns only its received bytes, not the pooled receive buffer.
	return &plugin.DNSResponse{Wire: append([]byte(nil), wire[:n]...), ReceivedAt: time.Now(), Origin: "relay"}, nil
}

func readDNSFrame(conn io.Reader) ([]byte, error) {
	var prefix [2]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return nil, err
	}
	wire := make([]byte, int(binary.BigEndian.Uint16(prefix[:])))
	_, err := io.ReadFull(conn, wire)
	return wire, err
}

func writeDNSFrame(conn io.Writer, wire []byte) error {
	if len(wire) > 65535 {
		return errors.New("DNS frame exceeds 65535 bytes")
	}
	frame := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(frame, uint16(len(wire)))
	copy(frame[2:], wire)
	for len(frame) > 0 {
		n, err := conn.Write(frame)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}

func (c *ControlPlane) serveDNSTCP(conn net.Conn, src, dst netip.AddrPort, identity bpfRoutingResult) error {
	r := c.dnsRelay
	if r == nil || !r.admit() {
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
		if err := writeDNSFrame(conn, wire); err != nil {
			return err
		}
		refreshRead()
		return nil
	}
	streams := make(map[netip.AddrPort]*dnsStream)
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
	terminal := func(operation context.Context, request *plugin.DNSRequest) (*plugin.DNSResponse, error) {
		if request.Independent {
			upstream, err := request.DialContext(operation, "tcp", request.Destination.String(), "")
			if err != nil {
				return nil, err
			}
			stream := newDNSStream(upstream, func([]byte) error { return nil }, func() {})
			defer stream.close()
			return stream.exchange(operation, request)
		}
		streamsMu.Lock()
		stream := streams[request.Destination]
		if stream == nil {
			if len(streams) >= 16 {
				streamsMu.Unlock()
				return nil, fmt.Errorf("too many DNS destinations on one connection")
			}
			upstream, err := request.DialContext(operation, "tcp", request.Destination.String(), "")
			if err != nil {
				streamsMu.Unlock()
				return nil, err
			}
			stream = newDNSStream(upstream, write, endRead)
			streams[request.Destination] = stream
		}
		streamsMu.Unlock()
		return stream.exchange(operation, request)
	}
	concurrency := make(chan struct{}, 32)
	refreshRead()
	for {
		wire, err := readDNSFrame(conn)
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
		if !r.admit() {
			return fmt.Errorf("DNS request capacity exhausted")
		}
		request := template.Copy()
		request.Wire = wire
		if message := unpackDNSMessage(wire); message != nil && !message.Response {
			request.Message = message
		}
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
