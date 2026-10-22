// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"math/rand/v2"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/internal/routingabi"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	log "github.com/sirupsen/logrus"
)

// fallbackTokens names a group's interruptible fallback generations in the
// kernel. A token stays live until its generation's lease aborts; flows
// stamped with an ended token are interrupted like flows of a changed device
// route. Generations survive reloads, so their tokens are Runtime-wide.
// Pinned flow state outlives the process but the live set does not. A random
// starting point reduces the chance of reissuing a previous process's token.
type fallbackTokens struct {
	mu     sync.Mutex
	live   *ebpf.Map
	tokens map[*netproxy.Lease]uint32
	next   uint32
}

func newFallbackTokens(live *ebpf.Map) *fallbackTokens {
	return &fallbackTokens{live: live, tokens: make(map[*netproxy.Lease]uint32), next: rand.Uint32()}
}

// token returns zero, which the kernel never interrupts, without a
// generation or when the live set cannot hold another one.
func (f *fallbackTokens) token(generation *netproxy.Lease) uint32 {
	if generation == nil {
		return 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if token, ok := f.tokens[generation]; ok {
		return token
	}
	// The kernel stores tokens in fields where these values mark other states.
	f.next++
	for f.next == 0 || f.next == routingabi.FALLBACK_TOKEN_RESERVED {
		f.next++
	}
	token := f.next
	if err := f.live.Update(token, uint8(1), ebpf.UpdateNoExist); err != nil {
		log.WithError(err).Warn("Cannot track a direct fallback generation; its kernel-forwarded connections stay open when the group recovers")
		token = 0
	}
	f.tokens[generation] = token
	generation.AfterAbort(func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		delete(f.tokens, generation)
		if token != 0 {
			_ = f.live.Delete(token)
		}
	})
	return token
}
