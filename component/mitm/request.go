// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"errors"
	"net/http"

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
	r = h.traceUpstream(r)
	response, err := transport.RoundTrip(r)
	if response != nil && h.options.Logger.Logger.IsLevelEnabled(log.TraceLevel) {
		h.requestLogger(r).WithFields(log.Fields{
			"event": "mitm_upstream_response", "host": r.URL.Hostname(),
			"upstream_protocol": response.Proto, "upstream_status": response.StatusCode,
			"content_length": response.ContentLength,
		}).Trace("MITM upstream response headers received")
	}
	if err != nil && r.Context().Err() == nil {
		connection, request := plugin.IDs(r.Context())
		h.options.Logger.WithFields(log.Fields{
			"event": "upstream_error", "connection_id": connection, "request_id": request,
			"method": r.Method, "host": r.URL.Hostname(),
		}).WithError(errors.New(diagnosticError(err))).Debug("MITM upstream request failed")
	}
	return response, err
}
