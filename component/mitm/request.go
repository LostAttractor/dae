// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"errors"
	"net/http"

	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/component/plugin"
	log "github.com/sirupsen/logrus"
)

// Retry ownership ends when the transport returns headers. Upload cursors can
// still be active then; their lifetime belongs to the transport, not the cache.
func (h *Host) roundTrip(transport http.RoundTripper, r *http.Request) (*http.Response, error) {
	if err := prepareRequestFraming(r); err != nil {
		_ = r.Body.Close()
		return nil, err
	}
	release := prepareRequestReplay(r, plugin.BodyMemory)
	defer release()
	response, err := transport.RoundTrip(r)
	if err != nil && r.Context().Err() == nil {
		connection, request := plugin.IDs(r.Context())
		message := resource.RedactError(err).Error()
		if len(message) > 1024 {
			message = message[:1024] + "..."
		}
		h.options.Logger.WithFields(log.Fields{
			"event": "upstream_error", "connection_id": connection, "request_id": request,
			"method": r.Method, "host": r.URL.Hostname(),
		}).WithError(errors.New(message)).Debug("MITM upstream request failed")
	}
	return response, err
}
