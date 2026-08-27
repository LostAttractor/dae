/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"structs"
	"syscall"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	protocolDirect "github.com/daeuniverse/outbound/protocol/direct"
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type RouteParam struct {
	routingResult *bpfRoutingResult
	networkType   *common.NetworkType
	Domain        string
	Src           netip.AddrPort
	Dest          netip.AddrPort
}

type DialOption struct {
	DialTarget        string
	Dialer            *dialer.Dialer
	connectionDialer  netproxy.Dialer
	Outbound          *outbound.DialerGroup
	Direct            bool
	FallbackIpVersion bool
	FallbackDialer    bool
}

const routeLogMessage = "route"

func (o *DialOption) dialerForConnection() netproxy.Dialer {
	if o.connectionDialer != nil {
		return o.connectionDialer
	}
	return o.Dialer
}

func IsNetError(err error) (netErr net.Error, ok bool) {
	ok = errors.As(err, &netErr)
	return
}

// closeInBackground starts cleanup without making control-plane shutdown wait
// for transports whose Close may block. It does not guarantee cleanup completion.
func closeInBackground(closer io.Closer) {
	if closer != nil {
		go func() { _ = closer.Close() }()
	}
}

func (c *ControlPlane) RouteDialOption(ctx context.Context, p *RouteParam) (dialOption *DialOption, err error) {
	// TODO: Why not directly transfer routingResult
	outboundIndex := consts.OutboundIndex(p.routingResult.Outbound)
	mark := p.routingResult.Mark

	verified, shouldReroute, err := c.verifySniff(ctx, p.Dest, p.Domain)
	if err != nil {
		return nil, err
	}
	switch {
	case c.rerouteMode == consts.RerouteMode_WhileNeed && shouldReroute,
		c.rerouteMode == consts.RerouteMode_Force:
		outboundIndex = consts.OutboundControlPlaneRouting
	}

	switch outboundIndex {
	case consts.OutboundDirect:
	case consts.OutboundControlPlaneRouting:
		domain := p.Domain
		if !verified {
			domain = ""
		}
		if outboundIndex, mark, _, err = c.Route(p.Src, p.Dest, domain, p.networkType.L4Proto.ToL4ProtoType(), p.routingResult); err != nil {
			oops.Wrap(err)
			return
		}
		if log.IsLevelEnabled(log.TraceLevel) {
			log.Tracef("outbound: %v => <Control Plane Routing>",
				outboundIndex.String(),
			)
		}
	default:
	}
	p.routingResult.Mark = mark
	// TODO: Set-up ip to domain mapping and show domain if possible.
	if int(outboundIndex) >= len(c.outbounds) {
		if len(c.outbounds) == int(consts.OutboundUserDefinedMin) {
			err = oops.Errorf("traffic was dropped due to no-load configuration")
			return
		}
		err = oops.Errorf("outbound id from bpf is out of range: %v not in [0, %v]", outboundIndex, len(c.outbounds)-1)
		return
	}
	outbound := c.outbounds[outboundIndex]
	dialTarget, dialIp := c.ChooseDialTarget(outboundIndex, p.Dest, p.Domain, verified && c.dialTargetOverride)
	dialer, fallback, err := outbound.SelectFallbackIpVersion(p.networkType, dialIp)
	fallbackDialer := false
	selectedOutboundIndex := outboundIndex
	if err != nil {
		dialer, err = c.outbounds[c.noConnectivityOutbound].Select(p.networkType)
		if err != nil {
			panic(fmt.Sprintf("fail to get fallback dialer %v(%v): %v", c.outbounds[c.noConnectivityOutbound], c.noConnectivityOutbound, err))
		}
		fallbackDialer = true
		selectedOutboundIndex = c.noConnectivityOutbound
	}
	return &DialOption{
		DialTarget:        dialTarget,
		Dialer:            dialer,
		connectionDialer:  c.directDialerForMark(selectedOutboundIndex, mark),
		Outbound:          outbound,
		Direct:            selectedOutboundIndex == consts.OutboundDirect,
		FallbackIpVersion: fallback,
		FallbackDialer:    fallbackDialer,
	}, nil
}

func (c *ControlPlane) directDialerForMark(outboundIndex consts.OutboundIndex, mark uint32) netproxy.Dialer {
	if outboundIndex != consts.OutboundDirect || mark == 0 || mark == c.soMarkFromDae {
		return nil
	}
	if cached, ok := c.markedDirectDialers.Load(mark); ok {
		return cached.(netproxy.Dialer)
	}
	d := protocolDirect.NewDirectDialer(protocolDirect.Option{
		FallbackDNS: c.fallbackResolver,
		Mptcp:       c.mptcp,
		Mark:        int(mark),
	})
	actual, _ := c.markedDirectDialers.LoadOrStore(mark, d)
	return actual.(netproxy.Dialer)
}

func routingLogFields(routingResult *bpfRoutingResult, interfaceName string) log.Fields {
	fields := make(log.Fields)
	if routingResult.Pid != 0 {
		fields["pid"] = routingResult.Pid
	}
	if pname := ProcessName2String(routingResult.Pname[:]); pname != "" {
		fields["pname"] = pname
	}
	if interfaceName != "" {
		fields["interface"] = interfaceName
	}
	if routingResult.Dscp != 0 {
		fields["dscp"] = routingResult.Dscp
	}
	if routingResult.Mac != [6]uint8{} {
		fields["mac"] = Mac2String(routingResult.Mac[:])
	}
	return fields
}

func routeLogFields(routingResult *bpfRoutingResult, interfaceName, network, source, destination string) log.Fields {
	fields := routingLogFields(routingResult, interfaceName)
	fields["action"] = "forward"
	fields["network"] = network
	fields["source"] = source
	fields["destination"] = destination
	return fields
}

func (c *ControlPlane) interfaceName(ifindex uint32) string {
	if ifindex == 0 || c == nil || c.core == nil || c.core.ifmgr == nil {
		return ""
	}
	return c.core.ifmgr.NameByIndex(int(ifindex))
}

func (c *ControlPlane) logDial(src, dst netip.AddrPort, domain string, dialOption *DialOption, network string, routingResult *bpfRoutingResult) {
	if log.IsLevelEnabled(log.InfoLevel) {
		destinationIP := RefineAddrPortToShow(dst)
		fields := routeLogFields(
			routingResult,
			c.interfaceName(routingResult.Ifindex),
			network,
			RefineSourceToShow(src, dst.Addr()),
			dialOption.DialTarget,
		)
		fields["target_kind"] = dialOption.Outbound.TargetKind.String()
		if dialOption.DialTarget != destinationIP {
			fields["destination_ip"] = destinationIP
		}
		if domain != "" {
			fields["sniffed"] = domain
		}
		fields["dialer"] = dialOption.Dialer.Name
		if consts.OutboundIndex(routingResult.Outbound) == consts.OutboundControlPlaneRouting {
			fields["control_plane_route"] = true
		}
		if dialOption.Outbound.Name == consts.OutboundBlock.String() {
			fields["action"] = "block"
		}
		if dialOption.FallbackIpVersion || dialOption.FallbackDialer {
			fields["fallback"] = true
		}
		if dialOption.FallbackDialer {
			fields["original_outbound"] = dialOption.Outbound.Name
			if policy := dialOption.Outbound.DisplayPolicy(); policy != "" {
				fields["original_policy"] = policy
			}
		} else {
			fields["outbound"] = dialOption.Outbound.Name
			if policy := dialOption.Outbound.DisplayPolicy(); policy != "" {
				fields["policy"] = policy
			}
		}
		log.WithFields(fields).Info(routeLogMessage)
	}
}

func (c *ControlPlane) Route(src, dst netip.AddrPort, domain string, l4proto consts.L4ProtoType, routingResult *bpfRoutingResult) (outboundIndex consts.OutboundIndex, mark uint32, must bool, err error) {
	ipVersion := consts.IpVersionFromAddr(dst.Addr())
	bSrc := src.Addr().As16()
	bDst := dst.Addr().As16()
	return c.routingMatcher.Match(
		bSrc[:],
		bDst[:],
		src.Port(),
		dst.Port(),
		ipVersion,
		l4proto,
		domain,
		routingResult.Pname,
		routingResult.Ifindex,
		routingResult.Dscp,
		append([]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, routingResult.Mac[:]...),
	)
}

func (c *controlPlaneCore) RetrieveRoutingResult(src, dst netip.AddrPort, l4proto uint8) (result *bpfRoutingResult, err error) {
	srcIp6 := src.Addr().As16()
	dstIp6 := dst.Addr().As16()

	tuples := &bpfTuplesKey{
		Sip: struct {
			_       structs.HostLayout
			U6Addr8 [16]uint8
		}{U6Addr8: srcIp6},
		Sport: common.Htons(src.Port()),
		Dip: struct {
			_       structs.HostLayout
			U6Addr8 [16]uint8
		}{U6Addr8: dstIp6},
		Dport:   common.Htons(dst.Port()),
		L4proto: l4proto,
	}

	var routingResult bpfRoutingResult
	if err := c.bpf.RoutingTuplesMap.Lookup(tuples, &routingResult); err != nil {
		return nil, fmt.Errorf("reading map: key [%v, %v, %v]: %w", src.String(), l4proto, dst.String(), err)
	}
	return &routingResult, nil
}

func RetrieveOriginalDest(oob []byte) netip.AddrPort {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.AddrPort{}
	}
	for _, msg := range msgs {
		if msg.Header.Level == syscall.SOL_IP && msg.Header.Type == syscall.IP_RECVORIGDSTADDR {
			ip := msg.Data[4:8]
			port := binary.BigEndian.Uint16(msg.Data[2:4])
			return netip.AddrPortFrom(netip.AddrFrom4(*(*[4]byte)(ip)), port)
		} else if msg.Header.Level == syscall.SOL_IPV6 && msg.Header.Type == unix.IPV6_RECVORIGDSTADDR {
			ip := msg.Data[8:24]
			port := binary.BigEndian.Uint16(msg.Data[2:4])
			return netip.AddrPortFrom(netip.AddrFrom16(*(*[16]byte)(ip)), port)
		}
	}
	return netip.AddrPort{}
}

func checkIpforward(ifname string, ipversion consts.IpVersionStr) error {
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/forwarding", ipversion, ifname)
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if bytes.Equal(bytes.TrimSpace(b), []byte("1")) {
		return nil
	}
	return fmt.Errorf("ipforward on %v is off: %v; see docs of dae for help", ifname, path)
}

func CheckIpforward(ifname string) error {
	if err := checkIpforward(ifname, consts.IpVersionStr_4); err != nil {
		return err
	}
	if err := checkIpforward(ifname, consts.IpVersionStr_6); err != nil {
		return err
	}
	return nil
}

func setForwarding(ifname string, ipversion consts.IpVersionStr, val string) error {
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/forwarding", ipversion, ifname)
	err := os.WriteFile(path, []byte(val), 0644)
	if err != nil {
		return err
	}
	return nil
}

func SetIpv4forward(val string) error {
	err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte(val), 0644)
	if err != nil {
		return err
	}
	return nil
}

func SetForwarding(ifname string, val string) {
	_ = setForwarding(ifname, consts.IpVersionStr_4, val)
	_ = setForwarding(ifname, consts.IpVersionStr_6, val)
}

func checkSendRedirects(ifname string, ipversion consts.IpVersionStr) error {
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/send_redirects", ipversion, ifname)
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if bytes.Equal(bytes.TrimSpace(b), []byte("0")) {
		return nil
	}
	return fmt.Errorf("send_directs on %v is on: %v; see docs of dae for help", ifname, path)
}

func CheckSendRedirects(ifname string) error {
	if err := checkSendRedirects(ifname, consts.IpVersionStr_4); err != nil {
		return err
	}
	return nil
}

func setSendRedirects(ifname string, ipversion consts.IpVersionStr, val string) error {
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/send_redirects", ipversion, ifname)
	err := os.WriteFile(path, []byte(val), 0644)
	if err != nil {
		return err
	}
	return nil
}

func SetSendRedirects(ifname string, val string) {
	_ = setSendRedirects(ifname, consts.IpVersionStr_4, val)
}

func ProcessName2String(pname []uint8) string {
	return string(bytes.TrimRight(pname[:], string([]byte{0})))
}

func Mac2String(mac []uint8) string {
	ori := []byte(hex.EncodeToString(mac))
	// Insert ":".
	b := make([]byte, len(ori)/2*3-1)
	for i, j := 0, 0; i < len(ori); i, j = i+2, j+3 {
		copy(b[j:j+2], ori[i:i+2])
		if j+2 < len(b) {
			b[j+2] = ':'
		}
	}
	return string(b)
}
