/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"fmt"
	"net"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

type blockDialer struct {
	DialCallback func()
}

func (d *blockDialer) DialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	switch network {
	case "tcp", "udp":
		d.DialCallback()
		return nil, net.ErrClosed
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *blockDialer) ListenPacket(ctx context.Context, addr string) (c net.PacketConn, err error) {
	d.DialCallback()
	return nil, net.ErrClosed
}

func NewBlockDialer(option *ExtraOption, dialCallback func()) (netproxy.Dialer, *Property) {
	return &blockDialer{DialCallback: dialCallback}, &Property{
		Name:     "block",
		Address:  "",
		Protocol: "",
		Link:     "",
	}
}
