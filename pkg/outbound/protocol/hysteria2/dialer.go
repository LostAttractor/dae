package hysteria2

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/hysteria2/client"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/hysteria2/udphop"
)

func init() {
	protocol.RegisterLayer("hysteria2", func(parent netproxy.Dialer, header protocol.Header) (netproxy.Layer, error) {
		dialer, err := NewDialer(parent, header)
		if err != nil {
			return netproxy.Layer{}, err
		}
		return netproxy.Layer{
			Data:      dialer,
			Sessions:  []netproxy.Session{dialer},
			Resources: []io.Closer{dialer},
		}, nil
	})
}

// Why Metadata?
type Dialer struct {
	*client.Client
}

type Feature1 struct {
	BandwidthConfig client.BandwidthConfig
	UDPHopInterval  time.Duration
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (*Dialer, error) {
	host, port := parseServerAddrString(header.ProxyAddress)
	config := &client.Config{
		TLSConfig: tls.Config{
			ServerName:            header.TlsConfig.ServerName,
			InsecureSkipVerify:    header.TlsConfig.InsecureSkipVerify,
			VerifyPeerCertificate: header.TlsConfig.VerifyPeerCertificate,
			RootCAs:               header.TlsConfig.RootCAs,
		},
		Auth:       header.User,
		FastOpen:   true,
		NextDialer: nextDialer,
	}

	if header.SNI == "" {
		config.TLSConfig.ServerName = host
	}
	if header.Password != "" {
		config.Auth = header.User + ":" + header.Password
	}
	if feature := header.Feature1; feature != nil {
		config.BandwidthConfig = feature.(*Feature1).BandwidthConfig
		config.UDPHopInterval = feature.(*Feature1).UDPHopInterval
	}

	if isPortHoppingPort(port) {
		ports := udphop.ParsePortUnion(port)
		if ports == nil {
			return nil, udphop.InvalidPortError{PortStr: port}
		}
		portList := ports.Ports()
		config.ResolveAddr = func(ctx context.Context) (net.Addr, error) {
			addr, err := netproxy.ResolveUDPAddr(ctx, nextDialer, net.JoinHostPort(host, "0"))
			if err != nil {
				return nil, err
			}
			return &udphop.UDPHopAddr{IP: addr.IP, Zone: addr.Zone, Ports: portList, PortStr: port}, nil
		}
	} else {
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return nil, udphop.InvalidPortError{PortStr: port}
		}
		config.ResolveAddr = func(ctx context.Context) (net.Addr, error) {
			return netproxy.ResolveUDPAddr(ctx, nextDialer, net.JoinHostPort(host, port))
		}
	}

	client, err := client.NewClient(config)
	if err != nil {
		return nil, err
	}

	return &Dialer{
		Client: client,
	}, nil
}

// parseServerAddrString parses server address string.
// Server address can be in either "host:port" or "host" format (in which case we assume port 443).
func parseServerAddrString(addrStr string) (host, port string) {
	h, p, err := net.SplitHostPort(addrStr)
	if err != nil {
		return strings.TrimSuffix(strings.TrimPrefix(addrStr, "["), "]"), "443"
	}
	return h, p
}

// isPortHoppingPort returns whether the port string is a port hopping port.
// We consider a port string to be a port hopping port if it contains "-" or ",".
func isPortHoppingPort(port string) bool {
	return strings.Contains(port, "-") || strings.Contains(port, ",")
}
