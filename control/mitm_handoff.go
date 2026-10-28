// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"

	"github.com/daeuniverse/dae/component/mitm"
)

// The publication owner completes the handoff after activation or terminal failure.
type mitmHandoff struct {
	done   chan struct{}
	planes [2]*planeHTTP
	err    error
}

func (c *planeHTTP) admitMITM(ctx context.Context) (*mitm.Admission, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c.mitmMu.RLock()
		handoff := c.mitmHandoff
		if handoff == nil {
			admission, err := c.mitmHost.Admit()
			c.mitmMu.RUnlock()
			return admission, err
		}
		c.mitmMu.RUnlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-handoff.done:
		}
		if handoff.err != nil {
			return nil, handoff.err
		}
	}
}

func (c *planeHTTP) pauseMITM(next *planeHTTP) *mitmHandoff {
	handoff := &mitmHandoff{done: make(chan struct{}), planes: [2]*planeHTTP{c, next}}
	c.mitmMu.Lock()
	c.mitmHandoff = handoff
	c.mitmMu.Unlock()
	if next != c {
		next.mitmMu.Lock()
		next.mitmHandoff = handoff
		next.mitmMu.Unlock()
	}
	return handoff
}

func (h *mitmHandoff) complete(err error) {
	h.err = err
	if err == nil {
		for _, plane := range h.planes {
			plane.mitmMu.Lock()
			if plane.mitmHandoff == h {
				plane.mitmHandoff = nil
			}
			plane.mitmMu.Unlock()
		}
	}
	h.planes = [2]*planeHTTP{}
	close(h.done)
}
