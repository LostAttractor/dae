package direct

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/common"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

type Option struct {
	// Resolver is supplied by the owner; nil uses net.DefaultResolver.
	// Socket marks apply to data sockets. DNS transport policy belongs to Resolver.
	Resolver  *net.Resolver
	Mptcp     bool
	Mark      int
	Interface string
	IPVersion int // 0, 4 or 6; applies to data sockets, not Resolver's DNS transport.
}

type directDialer struct {
	dialer    net.Dialer
	ipVersion string
}

func NewDirectDialer(option Option) netproxy.Dialer {
	resolver := option.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	d := &directDialer{dialer: net.Dialer{Resolver: resolver}}
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
	return d.dialer.DialContext(ctx, network, addr)
}

func (d *directDialer) ResolveUDPAddr(ctx context.Context, address string) (*net.UDPAddr, error) {
	return common.ResolveUDPAddrContext(ctx, d.dialer.Resolver, "ip"+d.ipVersion, address)
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
