package control

import (
	"context"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/surgemodule"
	"github.com/daeuniverse/dae/pkg/config_parser"
	log "github.com/sirupsen/logrus"
)

func (c *ControlPlane) SurgeStatus() surgemodule.Status {
	if c.surge == nil {
		return surgemodule.Status{}
	}
	return c.surge.Status()
}

// Client selection only gates MITM after routing has selected the outbound.
// A denied client continues through the ordinary dial and buffered TCP relay.
func (c *ControlPlane) shouldMITMClient(domain string, src, dst netip.AddrPort, result *bpfRoutingResult, option *DialOption) bool {
	if c.surge == nil || option.Outbound.Name == consts.OutboundBlock.String() || !c.surge.Match(domain, dst.Port()) {
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
		}).Info("surge")
	}
	return enabled
}

// mitmSelection is shared by the traffic gate and the device API. An explicit
// device setting takes precedence over the configured IP/MAC allowlist.
func (c *ControlPlane) mitmSelection(ip netip.Addr, mac [6]byte) (enabled bool, override *bool) {
	if enabled, exists := c.settings.MITM(mac); exists {
		return enabled, &enabled
	}
	return c.mitmClients.Match(ip, mac), nil
}

// enableSurgeRouting captures allowlisted domains even when their ordinary
// route is direct (normally kept entirely in eBPF). The userspace matcher skips
// control_plane_routing markers and still selects the original configured route.
func (p *preparedRules) enableSurgeRouting(engine *surgemodule.Engine) {
	if engine == nil {
		return
	}
	p.enableSurgeModuleRules(engine)
	var patterns []*config_parser.Param
	seen := make(map[string]bool)
	for _, host := range engine.Hostnames() {
		if name, _, err := net.SplitHostPort(host); err == nil {
			host = name
		} else if strings.Count(host, ":") == 1 {
			host, _, _ = strings.Cut(host, ":")
		}
		host = strings.TrimSuffix(strings.ToLower(host), ".")
		pattern := regexp.QuoteMeta(host)
		pattern = strings.ReplaceAll(strings.ReplaceAll(pattern, `\*`, ".*"), `\?`, ".")
		pattern = "^" + pattern + "$"
		if !seen[pattern] {
			patterns = append(patterns, &config_parser.Param{Key: "regex", Val: pattern})
			seen[pattern] = true
		}
	}
	if len(patterns) == 0 {
		return
	}
	rule := &config_parser.RoutingRule{
		AndFunctions: []*config_parser.Function{
			{Name: "l4proto", Params: []*config_parser.Param{{Val: "tcp"}}},
			{Name: "domain", Params: patterns},
		},
		Outbound: config_parser.Function{Name: consts.OutboundControlPlaneRouting.String()},
	}
	p.routing = append([]*config_parser.RoutingRule{rule}, p.routing...)
}

func (c *ControlPlane) surgeDialContext(option *DialOption, host string, destination netip.AddrPort, path stats.Path) surgemodule.DialContext {
	selected := option.dialerForConnection()
	target := option.DialTarget
	return func(parent context.Context, network, address string) (net.Conn, error) {
		// Preserve dial_target_override and IP family for the original host.
		// A URL rewritten by a script uses the same selected outbound, but its
		// new authority is resolved by that outbound rather than the old IP.
		requestedHost, port, err := net.SplitHostPort(address)
		if err == nil && strings.EqualFold(strings.TrimSuffix(requestedHost, "."), strings.TrimSuffix(host, ".")) && port == strconv.Itoa(int(destination.Port())) {
			address = target
		} else if dst, err := netip.ParseAddrPort(address); err == nil {
			if rewritten, ok := c.destinationRewrites.Rewrite(dst, !option.Direct); ok {
				address = rewritten.String()
			}
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

type surgeCountedConn struct {
	net.Conn
	upload, download func(uint64)
}

func (c *surgeCountedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.upload(uint64(n))
	return n, err
}
func (c *surgeCountedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.download(uint64(n))
	return n, err
}
