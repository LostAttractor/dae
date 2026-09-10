// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"fmt"
	"net/http"

	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/component/mitm/plugin"
)

// Retry ownership ends when the transport returns headers. Upload cursors can
// still be active then; their lifetime belongs to the transport, not the cache.
func (h *Host) roundTrip(transport http.RoundTripper, r *http.Request) (*http.Response, error) {
	release := prepareRequestReplay(r, plugin.BodyMemory)
	defer release()
	response, err := transport.RoundTrip(r)
	if err != nil && r.Context().Err() == nil && h.options.Log != nil {
		connection, request := plugin.IDs(r.Context())
		message := resource.RedactError(err).Error()
		if len(message) > 1024 {
			message = message[:1024] + "..."
		}
		h.options.Log(fmt.Sprintf("mitm event=upstream_error connection_id=%q request_id=%q method=%q host=%q error=%q",
			connection, request, r.Method, r.URL.Hostname(), message))
	}
	return response, err
}
