package tuic

import (
	"context"
	"net"

	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/common"
)

type clientRing struct {
	*common.ClientRing[*clientImpl]
}

func newClientRing(newClient func(func(int64)) *clientImpl, reserved int64) *clientRing {
	return &clientRing{common.NewClientRing(newClient, reserved)}
}

func (r *clientRing) DialContext(ctx context.Context, metadata *protocol.Metadata) (conn net.Conn, err error) {
	err = r.Allocate(ctx, true, func(ctx context.Context, client *clientImpl) error {
		conn, err = client.DialContext(ctx, metadata)
		return err
	})
	if err != nil && conn != nil {
		_ = conn.Close()
		conn = nil
	}
	return conn, err
}

func (r *clientRing) ListenPacket(ctx context.Context, metadata *protocol.Metadata) (conn net.PacketConn, err error) {
	err = r.Allocate(ctx, true, func(ctx context.Context, client *clientImpl) error {
		conn, err = client.ListenPacket(ctx, metadata)
		return err
	})
	if err != nil && conn != nil {
		_ = conn.Close()
		conn = nil
	}
	return conn, err
}
