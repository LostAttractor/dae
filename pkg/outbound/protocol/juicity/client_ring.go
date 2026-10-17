package juicity

import (
	"context"

	"github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/common"
)

type clientRing struct {
	*common.ClientRing[*clientImpl]
}

func newClientRing(newClient func(func(int64)) *clientImpl, reserved int64) *clientRing {
	return &clientRing{common.NewClientRing(newClient, reserved)}
}

func (r *clientRing) DialContext(ctx context.Context, metadata *Metadata) (conn *Conn, err error) {
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

func (r *clientRing) DialAuth(ctx context.Context, metadata *Metadata) (auth *UnderlayAuth, err error) {
	err = r.Allocate(ctx, false, func(ctx context.Context, client *clientImpl) error {
		auth, err = client.DialAuth(ctx, metadata)
		return err
	})
	if err != nil && auth != nil {
		auth.lease.Invalidate(err)
		auth = nil
	}
	return auth, err
}
