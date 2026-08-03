/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
)

type NetworkType struct {
	L4Proto   consts.L4ProtoStr
	IpVersion consts.IpVersionStr
}

func (t *NetworkType) String() string {
	return string(t.L4Proto) + string(t.IpVersion)
}

// networkTypeToIndex 将网络类型映射到集合索引
// collections:
// 0: TCP4 DNS
// 1: TCP6 DNS
// 2: UDP4 DNS
// 3: UDP6 DNS
func NetworkTypeToIndex(typ *NetworkType) int {
	switch typ.L4Proto {
	case consts.L4ProtoStr_TCP:
		switch typ.IpVersion {
		case consts.IpVersionStr_4:
			return 0
		case consts.IpVersionStr_6:
			return 1
		}
	case consts.L4ProtoStr_UDP:
		// UDP share the DNS check result.
		switch typ.IpVersion {
		case consts.IpVersionStr_4:
			return 2
		case consts.IpVersionStr_6:
			return 3
		}
	}
	panic("invalid network type")
}

func IndexToNetworkType(index int) *NetworkType {
	switch index {
	case 0:
		return &NetworkType{
			L4Proto:   consts.L4ProtoStr_TCP,
			IpVersion: consts.IpVersionStr_4,
		}
	case 1:
		return &NetworkType{
			L4Proto:   consts.L4ProtoStr_TCP,
			IpVersion: consts.IpVersionStr_6,
		}
	case 2:
		return &NetworkType{
			L4Proto:   consts.L4ProtoStr_UDP,
			IpVersion: consts.IpVersionStr_4,
		}
	case 3:
		return &NetworkType{
			L4Proto:   consts.L4ProtoStr_UDP,
			IpVersion: consts.IpVersionStr_6,
		}
	}
	panic("invalid network type")
}

// TODO: 现在 dialer 是否测速以及 dialerGroup 是否需要 AliveState 依赖于 AliveDialerSet 的注册
// 不需要AliveState的节点是不是应该始终Alive?
type collection struct {
	Latencies10   *LatenciesN
	MovingAverage time.Duration
	Alive         bool // Always not alive if there is no AliveDialerSet include the dialer.
	// 用于追踪连续错误
	// ErrorCount    int
	// LastErrorTime time.Time
}

func newCollection() *collection {
	return &collection{
		Latencies10: NewLatenciesN(10),
		Alive:       false,
	}
}

func (d *Dialer) GetAlive() bool {
	return d.collection.Alive
}

func (d *Dialer) Supported(typ *NetworkType) bool {
	return d.supported[NetworkTypeToIndex(typ)]
}

func parseIp46FromList(ip []string) (ip46 *netutils.Ip46, err error) {
	ip46 = new(netutils.Ip46)
	for _, ip := range ip {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return nil, oops.Errorf("invalid ip address: %w", err)
		}
		if addr.Is4() || addr.Is4In6() {
			ip46.Ip4 = addr
		} else if addr.Is6() {
			ip46.Ip6 = addr
		}
		if ip46.Ip4.IsValid() && ip46.Ip6.IsValid() {
			break
		}
	}
	return ip46, nil
}

type TcpCheckOption struct {
	Url *netutils.URL
	*netutils.Ip46
	Method string
}

func ParseTcpCheckOption(rawURL []string, method string) (opt *TcpCheckOption, err error) {
	if method == "" {
		method = http.MethodGet
	}
	if len(rawURL) == 0 {
		return nil, oops.Errorf("ParseTcpCheckOption: bad format: empty")
	}
	u, err := url.Parse(rawURL[0])
	if err != nil {
		return nil, err
	}
	var ip46 *netutils.Ip46
	if len(rawURL) > 1 {
		ip46, err = parseIp46FromList(rawURL[1:])
		if err != nil {
			return nil, oops.Wrapf(err, "ParseTcpCheckOption: failed to parse ip from list")
		}
	} else {
		ip46, err = netutils.ResolveIp46(u.Hostname())
		if err != nil {
			return nil, oops.Wrapf(err, "ParseTcpCheckOption: failed to resolve ip for %v", u.Hostname())
		}
		if !ip46.IsValid() {
			return nil, oops.Errorf("ResolveIp46: no valid ip for %v", u.Hostname())
		}
	}
	return &TcpCheckOption{
		Url:    &netutils.URL{URL: u},
		Ip46:   ip46,
		Method: method,
	}, nil
}

type CheckDnsOption struct {
	DnsHost string
	DnsPort uint16
	*netutils.Ip46
}

func ParseCheckDnsOption(dnsHostPort []string) (opt *CheckDnsOption, err error) {
	if len(dnsHostPort) == 0 {
		return nil, oops.Errorf("ParseCheckDnsOption: bad format: empty")
	}

	host, _port, err := net.SplitHostPort(dnsHostPort[0])
	if err != nil {
		return nil, oops.Wrapf(err, "ParseCheckDnsOption: failed to split host and port")
	}
	hostIP, err := netip.ParseAddr(host)
	hostIsIP := err == nil
	port, err := strconv.ParseUint(_port, 10, 16)
	if err != nil {
		return nil, oops.Errorf("bad port: %v", err)
	}
	var ip46 *netutils.Ip46
	if hostIsIP {
		if len(dnsHostPort) > 1 {
			return nil, oops.Errorf("ParseCheckDnsOption: format error, format should be hostport,ip,ip6,...")
		}
		ip46 = netutils.FromAddr(hostIP)
	} else if len(dnsHostPort) > 1 {
		ip46, err = parseIp46FromList(dnsHostPort[1:])
		if err != nil {
			return nil, oops.Wrapf(err, "ParseCheckDnsOption: failed to parse ip from list")
		}
	} else {
		ip46, err = netutils.ResolveIp46(host)
		if err != nil {
			return nil, oops.Wrapf(err, "ParseCheckDnsOption: failed to resolve ip for %v", host)
		}
		if !ip46.IsValid() {
			return nil, oops.Errorf("ResolveIp46: no valid ip for %v", host)
		}
	}
	return &CheckDnsOption{
		DnsHost: host,
		DnsPort: uint16(port),
		Ip46:    ip46,
	}, nil
}

type TcpCheckOptionRaw struct {
	opt    *TcpCheckOption
	mu     sync.Mutex
	Raw    []string
	Method string
}

func (c *TcpCheckOptionRaw) Option() (opt *TcpCheckOption, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.opt == nil {
		tcpCheckOption, err := ParseTcpCheckOption(c.Raw, c.Method)
		if err != nil {
			return nil, fmt.Errorf("failed to parse tcp_check_url: %w", err)
		}
		c.opt = tcpCheckOption
	}
	return c.opt, nil
}

type CheckDnsOptionRaw struct {
	opt *CheckDnsOption
	mu  sync.Mutex
	Raw []string
}

func (c *CheckDnsOptionRaw) Option() (opt *CheckDnsOption, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.opt == nil {
		udpCheckOption, err := ParseCheckDnsOption(c.Raw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse tcp_check_url: %w", err)
		}
		c.opt = udpCheckOption
	}
	return c.opt, nil
}

type CheckOption struct {
	networkType *NetworkType
	CheckFunc   func(typ *NetworkType) (ok bool, err error)
}

// // createTcpCheckFunc 创建TCP检查函数
// func (d *Dialer) createHttpCheckFunc(ipVersion consts.IpVersionStr, network string) func(typ *NetworkType) (ok bool, err error) {
// 	return func(typ *NetworkType) (ok bool, err error) {
// 		opt, err := d.TcpCheckOptionRaw.Option()
// 		if err != nil {
// 			return false, err
// 		}

// 		var ip netip.Addr
// 		switch ipVersion {
// 		case consts.IpVersionStr_4:
// 			ip = opt.Ip4
// 		case consts.IpVersionStr_6:
// 			ip = opt.Ip6
// 		}

// 		if !ip.IsValid() {
// 			log.WithFields(log.Fields{
// 				"link":    d.TcpCheckOptionRaw.Raw,
// 				"dialer":  d.Name,
// 				"network": typ.String(),
// 			}).Debugln("Skip check due to no DNS record.")
// 			return false, nil
// 		}

// 		return d.HttpCheck(opt.Url, ip, opt.Method, network)
// 	}
// }

// createDnsCheckFunc 创建DNS检查函数
// TODO: Context 应该随情况生成, 而非传入
// TODO: 为什么不直接编写一个 CheckFUnc
func (d *Dialer) createDnsCheckFunc(ipVersion consts.IpVersionStr, network string) func(typ *NetworkType) (ok bool, err error) {
	return func(typ *NetworkType) (ok bool, err error) {
		opt, err := d.CheckDnsOptionRaw.Option()
		if err != nil {
			return false, err
		}

		var ip netip.Addr
		switch ipVersion {
		case consts.IpVersionStr_4:
			ip = opt.Ip4
		case consts.IpVersionStr_6:
			ip = opt.Ip6
		}

		if !ip.IsValid() {
			log.WithFields(log.Fields{
				"link":    d.CheckDnsOptionRaw.Raw,
				"dialer":  d.Name,
				"network": typ.String(),
			}).Debugln("Skip check due to no DNS record.")
			return false, nil
		}

		return d.DnsCheck(netip.AddrPortFrom(ip, opt.DnsPort), network)
	}
}

func (d *Dialer) createCheckOptions() []*CheckOption {
	return []*CheckOption{
		// 优先 TCP, 因为 TCP 可以避免长时间占用 NAT 端口
		{
			networkType: &NetworkType{
				L4Proto:   consts.L4ProtoStr_TCP,
				IpVersion: consts.IpVersionStr_6,
			},
			CheckFunc: d.createDnsCheckFunc(consts.IpVersionStr_6, "tcp"),
		},
		{
			networkType: &NetworkType{
				L4Proto:   consts.L4ProtoStr_TCP,
				IpVersion: consts.IpVersionStr_4,
			},
			CheckFunc: d.createDnsCheckFunc(consts.IpVersionStr_4, "tcp"),
		},
		{
			networkType: &NetworkType{
				L4Proto:   consts.L4ProtoStr_UDP,
				IpVersion: consts.IpVersionStr_6,
			},
			CheckFunc: d.createDnsCheckFunc(consts.IpVersionStr_6, "udp"),
		},
		{
			networkType: &NetworkType{
				L4Proto:   consts.L4ProtoStr_UDP,
				IpVersion: consts.IpVersionStr_4,
			},
			CheckFunc: d.createDnsCheckFunc(consts.IpVersionStr_4, "udp"),
		},
	}
}

func (d *Dialer) ActivateCheck(wg *sync.WaitGroup) {
	if len(d.registeredAliveSets) == 0 {
		return
	}

	if d.InstanceOption.DisableCheck || d.checkActivated {
		return
	}
	d.checkActivated = true

	CheckOpts := d.createCheckOptions()

	wg.Add(1)

	go func() {
		// at startup, check all network types to determine which are supported
		checkOpt := d.runInitialCheck(CheckOpts)
		wg.Done()
		if checkOpt == nil {
			return
		}
		// after startup, only run check on one network type
		go d.startCheckTicker()
		go d.runCheckLoop(checkOpt)
	}()
}

func (d *Dialer) startCheckTicker() {
	// Sleep to avoid avalanche.
	time.Sleep(time.Duration(fastrand.Int63n(int64(d.CheckInterval))))
	d.tickerMu.Lock()
	d.ticker = time.NewTicker(d.CheckInterval)
	d.tickerMu.Unlock()
	for {
		select {
		case <-d.ctx.Done():
			return
		case t := <-d.ticker.C:
			d.checkCh <- t
		}
	}
}

// Manually start check.
func (d *Dialer) NotifyCheck() {
	select {
	case <-d.ctx.Done():
		return
	// If fail to push elem to chan, the check is in process.
	case d.checkCh <- time.Now():
		fmt.Printf("[DEBUG] NotifyCheck: %v\n", d.Name)
	default:
	}
}

func (d *Dialer) runCheckLoop(checkOpt *CheckOption) {
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-d.checkCh:
			for i := 0; i < 3; i++ {
				fmt.Printf("[DEBUG] runCheck: %v, count: %v\n", d.Name, i)
				ok, latency, err := d.Check(checkOpt)
				d.Update(ok, latency, checkOpt.networkType, err)
				if ok {
					break
				}
				time.Sleep(5 * time.Second)
			}
		}
	}
}

// TODO: Log
func (d *Dialer) runInitialCheck(checkOpts []*CheckOption) (opt *CheckOption) {
	var wg sync.WaitGroup
	var latency [4]time.Duration
	var err [4]error
	for _, opt := range checkOpts {
		i := NetworkTypeToIndex(opt.networkType)
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.supported[i], latency[i], err[i] = d.Check(opt)
			if d.supported[i] {
				log.WithFields(log.Fields{
					"network": opt.networkType.String(),
					"node":    d.Name,
					"last":    latency[i].Truncate(time.Millisecond).String(),
				}).Infoln("Inital Connectivity Check")
			} else {
				if log.IsLevelEnabled(log.TraceLevel) {
					log.WithFields(log.Fields{
						"network": opt.networkType.String(),
						"node":    d.Name,
					}).Infof("%+v\n", oops.Wrapf(err[i], "Inital Connectivity Check Failed"))
				} else {
					log.WithFields(log.Fields{
						"network": opt.networkType.String(),
						"node":    d.Name,
					}).Infoln(oops.Wrapf(err[i], "Inital Connectivity Check Failed"))
				}
			}
		}()
	}
	wg.Wait()
	for _, opt := range checkOpts {
		i := NetworkTypeToIndex(opt.networkType)
		if d.supported[i] {
			d.Update(d.supported[i], latency[i], opt.networkType, err[i])
			return opt
		}
	}
	d.Update(false, 0, nil, errors.Join(err[:]...))
	return nil
}

func (d *Dialer) MustGetLatencies10(typ *NetworkType) *LatenciesN {
	return d.collection.Latencies10
}

// RegisterAliveDialerSet is thread-safe.
func (d *Dialer) RegisterAliveDialerSet(a *AliveDialerSet) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.registeredAliveSets[a]++
}

// UnregisterAliveDialerSet is thread-safe.
func (d *Dialer) UnregisterAliveDialerSet(a *AliveDialerSet) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.registeredAliveSets, a)
}

func (d *Dialer) informDialerGroupUpdate() {
	// Inform DialerGroups to update state.
	// We use lock because AliveDialerSetSet is a reference of that in collection.
	d.mu.Lock()
	defer d.mu.Unlock()
	for a := range d.registeredAliveSets {
		a.NotifyLatencyChange(d, d.collection.Alive)
	}
}

func (d *Dialer) ReportUnavailable(typ *NetworkType, err error) {
	if !d.collection.Alive {
		return
	}

	if len(d.registeredAliveSets) == 0 {
		return
	}

	d.NotifyCheck()
}

func (d *Dialer) Update(ok bool, latency time.Duration, networkType *NetworkType, err error) {
	if ok {
		d.collection.Latencies10.AppendLatency(latency)
		avg, _ := d.collection.Latencies10.AvgLatency()
		d.collection.MovingAverage = (d.collection.MovingAverage + latency) / 2

		// // Reset error count.
		// if time.Since(d.collection.LastErrorTime) > 30*time.Second {
		// 	d.collection.ErrorCount = 0
		// }

		if !d.collection.Alive {
			log.WithFields(log.Fields{
				"network": networkType.String(),
				"node":    d.Name,
				"last":    latency.Truncate(time.Millisecond).String(),
				"avg_10":  avg.Truncate(time.Millisecond),
				"mov_avg": d.collection.MovingAverage.Truncate(time.Millisecond),
			}).Infoln("Connectivity Check")
		} else {
			log.WithFields(log.Fields{
				"network": networkType.String(),
				"node":    d.Name,
				"last":    latency.Truncate(time.Millisecond).String(),
				"avg_10":  avg.Truncate(time.Millisecond),
				"mov_avg": d.collection.MovingAverage.Truncate(time.Millisecond),
			}).Debugln("Connectivity Check")
		}
		d.collection.Alive = true
	} else {
		fields := log.Fields{
			"node": d.Name,
		}
		if networkType != nil {
			fields["network"] = networkType.String()
		}
		if d.collection.Alive {
			log.WithFields(fields).Warnln(oops.Wrapf(err, "Connectivity Check Failed"))
		} else {
			log.WithFields(fields).Infoln(oops.Wrapf(err, "Connectivity Check Failed"))
		}
		d.collection.Alive = false
	}
	d.informDialerGroupUpdate()
}

func (d *Dialer) Check(opts *CheckOption) (ok bool, latency time.Duration, err error) {
	start := time.Now()
	if ok, err = opts.CheckFunc(opts.networkType); ok {
		// Calc latency.
		latency = time.Since(start)
	} else {
		if err == nil {
			err = oops.Errorf("check func not working")
		} else if strings.HasSuffix(err.Error(), "network is unreachable") { // Append timeout if there is any error or unexpected status code.
			err = oops.Errorf("network is unreachable")
		} else if strings.HasSuffix(err.Error(), "no suitable address found") ||
			strings.HasSuffix(err.Error(), "non-IPv4 address") {
			err = oops.Errorf("IPv%v is not supported", opts.networkType.IpVersion)
		}
	}
	return
}

func (d *Dialer) HttpCheck(u *netutils.URL, ip netip.Addr, method string, network string) (ok bool, err error) {
	// HTTP(S) check.
	if method == "" {
		method = http.MethodGet
	}
	cli := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (c net.Conn, err error) {
				// Force to dial "ip".
				conn, err := d.Dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), u.Port()))
				if err != nil {
					return nil, err
				}
				return conn, nil
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.TODO(), consts.DefaultDialTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return false, err
	}
	resp, err := cli.Do(req)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr); netErr.Timeout() {
			err = fmt.Errorf("timeout")
		}
		return false, err
	}
	defer resp.Body.Close()
	// Judge the status code.
	if page := path.Base(req.URL.Path); strings.HasPrefix(page, "generate_") {
		if strconv.Itoa(resp.StatusCode) != strings.TrimPrefix(page, "generate_") {
			b, _ := io.ReadAll(resp.Body)
			buf := pool.GetBytesBuffer()
			defer pool.PutBytesBuffer(buf)
			_ = resp.Request.Write(buf)
			log.Debugln(buf.String(), "Resp: ", string(b))
			return false, fmt.Errorf("unexpected status code: %v", resp.StatusCode)
		}
		return true, nil
	} else {
		if resp.StatusCode < 200 || resp.StatusCode >= 500 {
			return false, fmt.Errorf("bad status code: %v", resp.StatusCode)
		}
		return true, nil
	}
}

func (d *Dialer) DnsCheck(dns netip.AddrPort, network string) (ok bool, err error) {
	addrs, err := netutils.ResolveNetip(d.Dialer, dns, consts.UdpCheckLookupHost, dnsmessage.TypeA, network)
	if err != nil {
		return false, err
	}
	if len(addrs) == 0 {
		return false, oops.Errorf("bad DNS response: no record")
	}
	return true, nil
}
