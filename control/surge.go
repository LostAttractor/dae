package control

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/mitmca"
	"github.com/daeuniverse/dae/component/surgemodule"
	log "github.com/sirupsen/logrus"
)

func (c *ControlPlane) SurgeStatus() surgemodule.Status {
	if c.mitmHost != nil {
		var status surgemodule.Status
		for _, instance := range c.mitmHost.Instances() {
			if engine, ok := instance.Plugin.(*surgemodule.Engine); ok {
				s := engine.Status()
				status.Enabled = true
				for _, module := range s.Modules {
					module.Instance = instance.ID
					status.Modules = append(status.Modules, module)
				}
			}
		}
		return status
	}
	return surgemodule.Status{}
}

// Client selection only gates MITM after routing has selected the outbound.
// A denied client continues through the ordinary dial and buffered TCP relay.
func (c *ControlPlane) shouldMITMClient(domain string, src, dst netip.AddrPort, result *bpfRoutingResult, option *DialOption) bool {
	matched := c.mitmHost != nil && c.mitmHost.Match(domain, dst.Port())
	if option.Outbound.Name == consts.OutboundBlock.String() || !matched {
		return false
	}
	src = common.ConvergeAddrPort(src)
	enabled, _ := c.mitmSelection(src.Addr(), result.Mac)
	if !enabled && log.IsLevelEnabled(log.InfoLevel) {
		mac := "unknown"
		if result.Mac != [6]byte{} {
			mac = net.HardwareAddr(result.Mac[:]).String()
		}
		log.WithFields(log.Fields{
			"event": "mitm_bypass", "host": domain, "port": dst.Port(),
			"source": src.String(), "mac": mac, "reason": "client_not_allowed",
		}).Info("mitm")
	}
	return enabled
}

func (c *ControlPlane) mitmAuthority() *mitmca.Authority {
	if c.mitmHost != nil {
		return c.mitmHost.Authority()
	}
	return nil
}

func (p *preparedRules) enableMITMPlan(plan mitm.Plan) {
	p.routing = slices.Concat(plan.EarlyRoutes, p.routing, plan.Routes)
	if len(plan.Scopes) != 0 {
		if p.capture == nil {
			p.capture = &routingCapture{}
		}
		p.capture.tcp = true
	}
}

// mitmSelection is shared by the traffic gate and the device API. An explicit
// device setting takes precedence over the configured IP/MAC allowlist.
func (c *ControlPlane) mitmSelection(ip netip.Addr, mac [6]byte) (enabled bool, override *bool) {
	if enabled, exists := c.settings.MITM(mac); exists {
		return enabled, &enabled
	}
	return c.mitmClients.Match(ip, mac), nil
}

func (c *ControlPlane) mitmDialContext(option *DialOption, host string, destination netip.AddrPort, path stats.Path) mitm.DialContext {
	selected := option.dialerForConnection()
	target := option.DialTarget
	return func(parent context.Context, network, address string) (net.Conn, error) {
		// Preserve dial_target_override and IP family for the original host.
		// A URL rewritten by a script uses the same selected outbound, but its
		// new authority is resolved by that outbound rather than the old IP.
		requestedHost, port, err := net.SplitHostPort(address)
		if err == nil && strings.EqualFold(strings.TrimSuffix(requestedHost, "."), strings.TrimSuffix(host, ".")) && port == strconv.Itoa(int(destination.Port())) {
			address = target
		}
		ctx, cancel := context.WithTimeout(parent, consts.DefaultDialTimeout)
		defer cancel()
		started := time.Now()
		conn, err := selected.DialContext(ctx, "tcp", address)
		if err != nil {
			stats.DefaultStore.RecordError(path)
			if parent.Err() == nil && option.Dialer.ChecksConnectivity() {
				if netErr, ok := IsNetError(err); ok && !netErr.Timeout() {
					option.Dialer.ReportDataPlaneFailure()
				}
			}
			return nil, err
		}
		stats.DefaultStore.RecordDial(path, time.Since(started))
		return conn, nil
	}
}

type mitmCountedConn struct {
	net.Conn
	upload, download func(uint64)
}

func (c *mitmCountedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.upload(uint64(n))
	return n, err
}
func (c *mitmCountedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.download(uint64(n))
	return n, err
}
