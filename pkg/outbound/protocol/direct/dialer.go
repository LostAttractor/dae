package direct

import (
	"context"
	"fmt"
	"iter"
	"net"
	"net/netip"
	"strconv"
	"strings"
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
	Lookup happyeyeballs.Lookup
	Mptcp  bool
	// Multipath, with Mptcp, chooses MPTCP per destination by whether it
	// negotiated MPTCP before; nil dials every TCP connection with MPTCP.
	Multipath *MultipathMemory
	Mark      int
	Interface string
	IPVersion int // 0, 4 or 6; applies to data sockets, not Resolver's DNS transport.
	// UserTimeout bounds unacknowledged data on TCP data sockets, closing
	// carriers of a black-holed path. Negotiated MPTCP connections cannot
	// set it; fallen-back ones set it on their only subflow.
	UserTimeout time.Duration
	// TCPFastOpen defers the SYN of plain TCP data sockets to their first
	// write once the kernel holds the server's cookie; MPTCP sockets keep a
	// full handshake. Only for peers the caller always writes to first: a
	// read before any write would never send the SYN, and CloseWrite before
	// any write resets the connection.
	TCPFastOpen bool
}

type directDialer struct {
	dialer      net.Dialer  // UDP, and TCP unless memory chooses multipath
	multipath   *net.Dialer // MPTCP; set with memory
	memory      *MultipathMemory
	mark        int
	iface       string
	lookup      happyeyeballs.Lookup
	ipVersion   string
	fastOpen    bool
	userTimeout time.Duration
}

func NewDirectDialer(option Option) netproxy.Dialer {
	resolver := option.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	d := &directDialer{dialer: net.Dialer{Resolver: resolver}, mark: option.Mark, iface: option.Interface, lookup: option.Lookup, fastOpen: option.TCPFastOpen, userTimeout: option.UserTimeout}
	if d.lookup == nil {
		d.lookup = resolver.LookupNetIP
	}
	if option.IPVersion != 0 {
		d.ipVersion = strconv.Itoa(option.IPVersion)
	}
	d.dialer.ControlContext = socketControl(option)
	d.dialer.SetMultipathTCP(option.Mptcp && option.Multipath == nil)
	if option.Mptcp && option.Multipath != nil {
		multipath := d.dialer
		multipath.SetMultipathTCP(true)
		// Probes learn from a completed handshake, also Go's TCP fallback.
		probe := option
		probe.TCPFastOpen = false
		multipath.ControlContext = socketControl(probe)
		d.multipath, d.memory = &multipath, option.Multipath
	}
	return d
}

func socketControl(option Option) func(context.Context, string, string, syscall.RawConn) error {
	return func(ctx context.Context, network, _ string, c syscall.RawConn) error {
		// Go retries any failed MPTCP dial as TCP, even one whose ctx has
		// ended; never start a connection for a dial that is already over.
		if err := ctx.Err(); err != nil {
			return err
		}
		if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
			return context.DeadlineExceeded
		}
		if option.Mark != 0 {
			if err := netproxy.SoMarkControl(c, option.Mark); err != nil {
				return err
			}
		}
		if option.Interface != "" {
			if err := netproxy.BindToDeviceControl(c, option.Interface); err != nil {
				return err
			}
		}
		if !strings.HasPrefix(network, "tcp") {
			return nil
		}
		if option.TCPFastOpen {
			setFastOpenConnect(c)
		}
		if option.UserTimeout > 0 {
			return setUserTimeout(c, option.UserTimeout)
		}
		return nil
	}
}

// dialPlain dials with d.dialer, the only TCP dialer that sets Fast Open.
func (d *directDialer) dialPlain(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.dialer.DialContext(ctx, network, address)
	if err == nil && d.fastOpen {
		conn = deferredConnect(conn.(*net.TCPConn))
	}
	return conn, err
}

func (d *directDialer) dialTCP(ctx context.Context, network string, ip netip.Addr, port string) (net.Conn, error) {
	address := net.JoinHostPort(ip.String(), port)
	number, err := strconv.ParseUint(port, 10, 16)
	if d.memory == nil || err != nil {
		return d.dialPlain(ctx, network, address)
	}
	key := multipathKey{d.mark, d.iface, netip.AddrPortFrom(ip.Unmap(), uint16(number))}
	table, multipath := d.memory.choose(key)
	if !multipath {
		return d.dialPlain(ctx, network, address)
	}
	conn, err := d.multipath.DialContext(ctx, network, address)
	result := multipathUnknown
	if err == nil {
		result = multipathIncapable
		if negotiated, _ := conn.(*net.TCPConn).MultipathTCP(); negotiated {
			result = multipathCapable
		}
	}
	d.memory.settle(table, key, result)
	if result == multipathIncapable && d.userTimeout > 0 {
		// The probe stays a single-path connection: the kernel serves TCP
		// options of a fallen-back socket from its only subflow, which the
		// MPTCP socket refused before connecting.
		raw, rawErr := conn.(*net.TCPConn).SyscallConn()
		if rawErr == nil {
			rawErr = setsockoptUserTimeout(raw, d.userTimeout)
		}
		if rawErr != nil {
			_ = conn.Close()
			return nil, rawErr
		}
	}
	return conn, err
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
	ip, err := netip.ParseAddr(host)
	if network[:3] == "tcp" {
		if err == nil {
			return d.dialTCP(ctx, network, ip, port)
		}
		return happyeyeballs.Race(ctx, func(ctx context.Context) iter.Seq2[netip.Addr, error] {
			return happyeyeballs.ResolveWith(ctx, d.lookup, "ip"+network[3:], host)
		}, func(ctx context.Context, ip netip.Addr) (net.Conn, error) {
			return d.dialTCP(ctx, network, ip, port)
		}, func(conn net.Conn) { _ = conn.Close() })
	}
	if err == nil {
		return d.dialer.DialContext(ctx, network, addr)
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
	config := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		return d.dialer.ControlContext(ctx, network, address, c)
	}}
	c, err := config.ListenPacket(ctx, "udp"+d.ipVersion, "")
	if err != nil {
		return nil, err
	}
	udp := c.(*net.UDPConn)
	return &PacketConn{UDPConn: udp, dialer: d, socket: netproxy.NewUDPSocket(udp)}, nil
}
