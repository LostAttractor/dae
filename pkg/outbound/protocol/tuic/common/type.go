package common

import (
	"context"
	"errors"
	"net"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/quic-go"
)

var (
	ErrClientClosed       = errors.New("client closed")
	ErrTooManyOpenStreams = errors.New("too many open streams")
	ErrHoldOn             = errors.New("hold on")
)

type DialFunc func(ctx context.Context, dialer netproxy.Dialer) (transport *quic.Transport, addr net.Addr, err error)

type UdpRelayMode uint8

const (
	QUIC UdpRelayMode = iota
	NATIVE
)
