// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"net/http"

	"github.com/daeuniverse/dae/component/mitm/plugin"
)

// Retry ownership ends when the transport returns headers. Upload cursors can
// still be active then; their lifetime belongs to the transport, not the cache.
func (h *Host) roundTrip(transport http.RoundTripper, r *http.Request) (*http.Response, error) {
	release := prepareRequestReplay(r, plugin.BodyMemory)
	defer release()
	return transport.RoundTrip(r)
}
