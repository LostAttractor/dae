// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/settings"
)

// Unit fixtures opt into the capabilities they exercise. No kernel objects,
// network subscriptions or background workers are created by the base builder.
type controlPlaneTestBuilder struct {
	t     testing.TB
	plane *ControlPlane
}

func newControlPlaneTestBuilder(t testing.TB) *controlPlaneTestBuilder {
	t.Helper()
	return &controlPlaneTestBuilder{t: t, plane: new(ControlPlane)}
}

func (b *controlPlaneTestBuilder) withLifecycle(endpoints *UdpEndpointPool) *controlPlaneTestBuilder {
	b.t.Helper()
	c := b.plane
	c.ctx, c.cancel = context.WithCancel(b.t.Context())
	c.planeTraffic = newPlaneTraffic(c.ctx, new(tcpConnectionSet), endpoints)
	c.dnsRelay = newDNSRelay()
	b.t.Cleanup(func() {
		c.cancelTCPSetups()
		c.cancel()
		c.udpTaskPool.close()
		_ = c.dnsRelay.Close()
	})
	return b
}

func (b *controlPlaneTestBuilder) withSettings() *controlPlaneTestBuilder {
	b.t.Helper()
	store, err := settings.Open(filepath.Join(b.t.TempDir(), "settings.json"))
	if err != nil {
		b.t.Fatal(err)
	}
	b.plane.settings = store
	return b
}

func (b *controlPlaneTestBuilder) withRouting(matcher *RoutingMatcher, builder *RoutingMatcherBuilder) *controlPlaneTestBuilder {
	c := b.plane
	c.routingMatcher, c.routingState, c.routingMatcherBuilder = matcher, builder.routingState, builder
	c.routingGeneration, c.sniffVerifyMode = 7, consts.SniffVerifyMode_None
	c.core = &controlPlaneCore{domainRegistry: newRoutingDomainRegistry()}
	return b
}

func (b *controlPlaneTestBuilder) build() *ControlPlane { return b.plane }
