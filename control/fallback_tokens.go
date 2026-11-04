// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"sync"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/internal/routingabi"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	log "github.com/sirupsen/logrus"
)

// Registries share a persistent sequence; the daemon instance lock excludes
// issuers in other processes.
var fallbackSequenceMu sync.Mutex

// fallbackTokens names interruptible fallback generations in the kernel.
// Freeze preserves their live set when kernel state must survive teardown.
// A cold Runtime owns a new live set and allocates identities from the persistent
// sequence, never reusing tokens still present in pinned flows.
type fallbackTokens struct {
	mu       sync.Mutex
	live     *ebpf.Map
	sequence *ebpf.Map
	tokens   map[*netproxy.Lease]uint32
	frozen   bool
}

func newFallbackTokens(live, sequence *ebpf.Map) *fallbackTokens {
	return &fallbackTokens{live: live, sequence: sequence, tokens: make(map[*netproxy.Lease]uint32)}
}

// issue persists the identity before granting it. Caller holds mu.
func (f *fallbackTokens) issue() uint32 {
	fallbackSequenceMu.Lock()
	defer fallbackSequenceMu.Unlock()
	var sequence uint64
	if err := f.sequence.Lookup(uint32(0), &sequence); err != nil {
		log.WithError(err).Warn("Cannot read the fallback token sequence; refusing kernel forwarding")
		return routingabi.FALLBACK_TOKEN_RESERVED
	}
	if sequence >= uint64(^uint32(0)) {
		log.Warn("Fallback token sequence exhausted; refusing kernel forwarding")
		return routingabi.FALLBACK_TOKEN_RESERVED
	}
	sequence = max(sequence, uint64(routingabi.FALLBACK_TOKEN_RESERVED)) + 1
	if err := f.sequence.Update(uint32(0), sequence, ebpf.UpdateAny); err != nil {
		log.WithError(err).Warn("Cannot advance the fallback token sequence; refusing kernel forwarding")
		return routingabi.FALLBACK_TOKEN_RESERVED
	}
	token := uint32(sequence)
	if err := f.live.Update(token, uint8(routingabi.FALLBACK_LEASE_LIVE), ebpf.UpdateNoExist); err != nil {
		log.WithError(err).Warn("Cannot track a direct fallback generation; refusing kernel forwarding for its connections")
		return routingabi.FALLBACK_TOKEN_RESERVED
	}
	return token
}

// Freeze preserves only the current live set while teardown releases groups.
func (f *fallbackTokens) Freeze() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.frozen {
		return
	}
	// An abort may precede registration of its token's callback.
	for generation, token := range f.tokens {
		if generation.AbortCause() != nil {
			if token != routingabi.FALLBACK_TOKEN_RESERVED {
				_ = f.live.Delete(token)
			}
			delete(f.tokens, generation)
		}
	}
	f.frozen = true
}

// token returns zero only for a fallback the connection policy cannot end.
// The reserved marker never grants kernel forwarding.
func (f *fallbackTokens) token(generation *netproxy.Lease) uint32 {
	if generation == nil {
		return 0
	}
	f.mu.Lock()
	if generation.AbortCause() != nil {
		f.mu.Unlock()
		return routingabi.FALLBACK_TOKEN_RESERVED
	}
	if token, ok := f.tokens[generation]; ok {
		f.mu.Unlock()
		return token
	}
	if f.frozen {
		f.mu.Unlock()
		return routingabi.FALLBACK_TOKEN_RESERVED
	}
	token := f.issue()
	f.tokens[generation] = token
	f.mu.Unlock()
	// AfterAbort may invoke the callback immediately for an already ended lease.
	generation.AfterAbort(func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		delete(f.tokens, generation)
		if !f.frozen && token != routingabi.FALLBACK_TOKEN_RESERVED {
			_ = f.live.Delete(token)
		}
	})
	return token
}
