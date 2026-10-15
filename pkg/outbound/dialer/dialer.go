package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

var (
	UnexpectedFieldErr  = fmt.Errorf("unexpected field")
	InvalidParameterErr = fmt.Errorf("invalid parameters")
)

type ExtraOption struct {
	AllowInsecure       bool
	TlsImplementation   string
	TlsFragment         bool
	TlsFragmentLength   string
	TlsFragmentInterval string
	UtlsImitate         string
	BandwidthMaxTx      string
	BandwidthMaxRx      string
	UDPHopInterval      time.Duration
}

type Property struct {
	Name     string
	Address  string
	Protocol string
	Link     string
}

// Builder constructs one outbound layer over an upstream data path. A failed
// Build retains responsibility for all resources it created and returns no
// partially owned Layer.
type Builder interface {
	Build(option *ExtraOption, upstream Upstream) (netproxy.Layer, error)
}

// Upstream exposes only data operations from the already built inner chain.
// Connections returned by those operations are passed through unchanged.
type Upstream struct{ data netproxy.Dialer }

func NewUpstream(data netproxy.Dialer) Upstream { return Upstream{data: data} }

func (u Upstream) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return u.data.DialContext(ctx, network, address)
}

func (u Upstream) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	return u.data.ListenPacket(ctx, address)
}

func (u Upstream) ResolveUDPAddr(ctx context.Context, address string) (*net.UDPAddr, error) {
	return netproxy.ResolveUDPAddr(ctx, u.data, address)
}

// BuildRuntime constructs a chain and transfers its ownership to one Runtime.
func BuildRuntime(base netproxy.Layer, option *ExtraOption, builders ...Builder) (*netproxy.Runtime, error) {
	if base.Data == nil {
		return nil, netproxy.ErrMissingDialer
	}
	for _, builder := range builders {
		layer, err := builder.Build(option, NewUpstream(base.Data))
		if err != nil {
			return nil, errors.Join(err, base.Close())
		}
		if err := base.Append(layer); err != nil {
			return nil, errors.Join(err, layer.Close(), base.Close())
		}
	}
	return netproxy.NewRuntime(base), nil
}
