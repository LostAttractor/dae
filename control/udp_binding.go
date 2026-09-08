package control

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	log "github.com/sirupsen/logrus"
)

func udpSourceKey(src netip.AddrPort) bpfUdpRoutingCacheKey {
	var key bpfUdpRoutingCacheKey
	key.Sip.U6Addr8 = src.Addr().As16()
	key.Sport = common.Htons(src.Port())
	return key
}

// The source lock serializes publication and removal of userspace bindings.
// Remove the initial kernel decision before releasing the binding: a packet
// cannot install the next lifetime's decision while this one still owns it.
func (c *ControlPlane) bindUDPSource(src netip.AddrPort, result *bpfRoutingResult) (func(), error) {
	key := udpSourceKey(src)
	bindings, decisions := c.core.bpf.UdpBindingsMap, c.core.bpf.UdpRoutingCacheMap
	if err := bindings.Update(&key, result.RouteEpoch, ebpf.UpdateNoExist); err != nil {
		return nil, fmt.Errorf("bind UDP source %v: %w", src, err)
	}
	return func() {
		for _, m := range []*ebpf.Map{decisions, bindings} {
			if err := m.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				log.WithFields(log.Fields{"source": src, "map": m.String()}).WithError(err).
					Warn("Failed to release UDP binding; stale source routing may remain")
			}
		}
	}, nil
}
