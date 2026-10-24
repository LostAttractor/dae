package direct

import (
	"context"
	"fmt"
	"iter"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/common"
	"github.com/daeuniverse/dae/pkg/outbound/happyeyeballs"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

type Option struct {
	// Resolver is supplied by the owner; nil uses net.DefaultResolver.
	// Socket marks apply to data sockets. DNS transport policy belongs to Resolver.
	Resolver *net.Resolver
	// Lookup, if set, answers the dialer's address lookups in front of
	// Resolver, for example from a cache. net.Dialer keeps Resolver.
	Lookup    happyeyeballs.Lookup
	Mptcp     bool
	Mark      int
	Interface string
	IPVersion int // 0, 4 or 6; applies to data sockets, not Resolver's DNS transport.
}

type directDialer struct {
	dialer    net.Dialer
	lookup    happyeyeballs.Lookup
	ipVersion string
}

func NewDirectDialer(option Option) netproxy.Dialer {
	resolver := option.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	d := &directDialer{dialer: net.Dialer{Resolver: resolver}, lookup: option.Lookup}
	if d.lookup == nil {
		d.lookup = resolver.LookupNetIP
	}
	if option.IPVersion != 0 {
		d.ipVersion = strconv.Itoa(option.IPVersion)
	}
	d.dialer.SetMultipathTCP(option.Mptcp)
	if option.Mark != 0 || option.Interface != "" {
		d.dialer.Control = func(_, _ string, c syscall.RawConn) error {
			if option.Mark != 0 {
				if err := netproxy.SoMarkControl(c, option.Mark); err != nil {
					return err
				}
			}
			if option.Interface != "" {
				return netproxy.BindToDeviceControl(c, option.Interface)
			}
			return nil
		}
	}
	return d
}

func (d *directDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		start := time.Now()
		defer func() { DirectDialLatency.Observe(time.Since(start).Seconds()) }()
	case "udp", "udp4", "udp6":
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
	if d.ipVersion != "" {
		if len(network) == 4 && network[3:] != d.ipVersion {
			return nil, fmt.Errorf("network %s conflicts with entry IPv%s", network, d.ipVersion)
		}
		network = network[:3] + d.ipVersion
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return d.dialer.DialContext(ctx, network, addr)
	}
	if network[:3] == "tcp" {
		return happyeyeballs.Race(ctx, func(ctx context.Context) iter.Seq2[netip.Addr, error] {
			return happyeyeballs.ResolveWith(ctx, d.lookup, "ip"+network[3:], host)
		}, func(ctx context.Context, ip netip.Addr) (net.Conn, error) {
			return d.dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		}, func(conn net.Conn) { _ = conn.Close() })
	}
	ips, err := d.lookup(ctx, "ip"+network[3:], host)
	if err != nil {
		return nil, err
	}
	// Like net.Dialer, try the resolver's order until one address connects.
	var first error
	for _, ip := range ips {
		conn, err := d.dialer.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
		if err == nil {
			return conn, nil
		}
		if first == nil {
			first = err
		}
		if ctx.Err() != nil {
			break
		}
	}
	if first == nil {
		first = &net.DNSError{Name: host, Err: "no suitable address", IsNotFound: true}
	}
	return nil, first
}

func (d *directDialer) ResolveUDPAddr(ctx context.Context, address string) (*net.UDPAddr, error) {
	return common.ResolveUDPAddrContext(ctx, d.lookup, "ip"+d.ipVersion, address)
}

func (d *directDialer) ListenPacket(ctx context.Context, _ string) (net.PacketConn, error) {
	config := net.ListenConfig{Control: d.dialer.Control}
	c, err := config.ListenPacket(ctx, "udp"+d.ipVersion, "")
	if err != nil {
		return nil, err
	}
	return &PacketConn{
		UDPConn: c.(*net.UDPConn),
		dialer:  d,
	}, nil
}
