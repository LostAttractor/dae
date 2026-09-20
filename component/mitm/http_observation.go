// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/component/plugin"
	log "github.com/sirupsen/logrus"
)

func (h *Host) requestLogger(r *http.Request) *log.Entry {
	connection, request := plugin.IDs(r.Context())
	return h.options.Logger.WithFields(log.Fields{
		"connection_id": connection, "request_id": request, "method": r.Method,
	})
}

// Diagnostics observe streaming reads and writes; they never consume or buffer
// additional body data. Paths are hashed so retries can be compared without
// recording URLs, credentials, metadata or response bodies.
type requestObservation struct {
	logger          *log.Entry
	started         time.Time
	writer          *observedResponseWriter
	response        *http.Response
	body            *observedResponseBody
	processingError error
	rejectionReason string
}

func (h *Host) observeRequest(w http.ResponseWriter, r *http.Request, scheme string, flow plugin.Flow) *requestObservation {
	if !h.options.Logger.Logger.IsLevelEnabled(log.DebugLevel) {
		return nil
	}
	path := sha256.Sum256([]byte(r.URL.EscapedPath()))
	requestedScheme := requestScheme(r, scheme)
	entry := h.requestLogger(r).WithFields(log.Fields{
		"host": flow.Host, "port": flow.Port, "client_protocol": r.Proto,
		"connection_host": flow.Host, "connection_scheme": scheme, "request_scheme": requestedScheme,
		"path_id": hex.EncodeToString(path[:8]),
	})
	if authority, ok := parseAuthority(r.Host, requestedScheme); ok {
		entry = entry.WithField("request_authority", authority.String())
	} else {
		entry = entry.WithField("request_authority", "invalid")
	}
	if flow.Source.IsValid() {
		entry = entry.WithField("source", flow.Source.String())
	}
	if flow.Destination.IsValid() {
		entry = entry.WithField("destination", flow.Destination.String())
	}
	entry.WithField("event", "mitm_request_begin").Trace("MITM request started")
	return &requestObservation{logger: entry, started: time.Now(), writer: &observedResponseWriter{ResponseWriter: w}}
}

func (o *requestObservation) authorityRejected(reason string) {
	o.rejectionReason = reason
	o.logger.WithFields(log.Fields{"event": "mitm_authority_rejected", "reason": reason}).Debug("MITM rejected request target")
}

func (o *requestObservation) observeResponse(response *http.Response) {
	o.response = response
	// Upgrades require io.ReadWriteCloser. Their tunnel lifetime and byte
	// accounting belong to ReverseProxy, rather than an HTTP response body.
	if response.StatusCode != http.StatusSwitchingProtocols {
		o.body = &observedResponseBody{ReadCloser: response.Body}
		response.Body = o.body
	}
}

func (o *requestObservation) finish(r *http.Request, failure any) {
	o.writer.mu.Lock()
	status, written, writeErr := o.writer.status, o.writer.written, o.writer.err
	o.writer.mu.Unlock()
	fields := log.Fields{
		"event": "mitm_request_end", "status": status, "response_written_bytes": written,
		"elapsed_ms": time.Since(o.started).Milliseconds(), "outcome": "completed",
	}
	if o.response != nil {
		fields["response_protocol"] = o.response.Proto
		if o.response.StatusCode == http.StatusSwitchingProtocols {
			fields["status"], fields["outcome"] = http.StatusSwitchingProtocols, "upgrade"
			delete(fields, "response_written_bytes")
		}
	}
	if o.body != nil {
		fields["response_read_bytes"], fields["body_eof"] = o.body.read, o.body.eof
		if o.body.err != nil {
			fields["read_error"] = diagnosticError(o.body.err)
		}
		// Trailer may be populated by the transport during Read. Inspect it
		// only after EOF, when the transport promises it is complete.
		if o.body.eof && strings.HasPrefix(strings.ToLower(o.response.Header.Get("Content-Type")), "application/grpc") {
			value := o.response.Trailer.Get("Grpc-Status")
			if value == "" {
				value = o.response.Header.Get("Grpc-Status")
			}
			fields["grpc_status"] = "missing"
			if value != "" {
				if code, err := strconv.ParseUint(value, 10, 32); err == nil {
					fields["grpc_status"] = code
				} else {
					fields["grpc_status"] = "invalid"
				}
			}
		}
	}
	if writeErr != nil {
		fields["write_error"] = diagnosticError(writeErr)
	}
	if o.processingError != nil {
		fields["outcome"], fields["processing_error"] = "processing_error", diagnosticError(o.processingError)
	} else if o.response == nil {
		fields["outcome"] = "local_rejection"
	}
	if o.rejectionReason != "" {
		fields["reason"] = o.rejectionReason
	}
	if failure != nil {
		fields["outcome"] = "aborted"
	}
	if writeErr != nil || o.body != nil && o.body.err != nil {
		fields["outcome"] = "transfer_error"
	}
	if cause := context.Cause(r.Context()); cause != nil {
		fields["context_error"] = diagnosticError(cause)
		fields["outcome"] = "canceled"
	}
	if writeErr != nil || o.body != nil && o.body.err != nil {
		fields["event"] = "mitm_response_failed"
		o.logger.WithFields(fields).Debug("MITM response transfer failed")
		fields["event"] = "mitm_request_end"
	}
	// Handler completion means writes were accepted by net/http, not that
	// the remote client received or accepted the response.
	o.logger.WithFields(fields).Trace("MITM request finished")
}

func diagnosticError(err error) string {
	message := resource.RedactError(err).Error()
	if len(message) > 1024 {
		message = message[:1024] + "..."
	}
	return message
}

type observedResponseBody struct {
	io.ReadCloser
	read int64
	eof  bool
	err  error
}

func (b *observedResponseBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.read += int64(n)
	if err == io.EOF {
		b.eof = true
	} else if err != nil {
		b.err = err
	}
	return n, err
}

// Unwrap preserves ResponseController deadlines and hijacking. FlushError
// captures errors from streaming flushes, including ReverseProxy's timer.
type observedResponseWriter struct {
	http.ResponseWriter
	mu      sync.Mutex
	status  int
	written int64
	err     error
}

func (w *observedResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *observedResponseWriter) WriteHeader(status int) {
	w.mu.Lock()
	if w.status == 0 && (status >= 200 || status == http.StatusSwitchingProtocols) {
		w.status = status
	}
	w.mu.Unlock()
	w.ResponseWriter.WriteHeader(status)
}

func (w *observedResponseWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.written += int64(n)
	if err != nil {
		w.err = err
	}
	return n, err
}

func (w *observedResponseWriter) FlushError() error {
	err := http.NewResponseController(w.ResponseWriter).Flush()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if err != nil {
		w.err = err
	}
	return err
}

func (h *Host) traceUpstream(r *http.Request) *http.Request {
	if !h.options.Logger.Logger.IsLevelEnabled(log.TraceLevel) {
		return r
	}
	started := time.Now()
	entry := h.requestLogger(r).WithField("host", r.URL.Hostname())
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			fields := log.Fields{
				"event": "mitm_upstream_connection", "reused": info.Reused,
				"was_idle": info.WasIdle, "idle_ms": info.IdleTime.Milliseconds(),
				"elapsed_ms": time.Since(started).Milliseconds(),
			}
			if info.Conn != nil {
				fields["upstream_local"], fields["upstream_peer"] = info.Conn.LocalAddr(), info.Conn.RemoteAddr()
			}
			entry.WithFields(fields).Trace("MITM upstream connection acquired")
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			fields := log.Fields{"event": "mitm_upstream_tls", "alpn": state.NegotiatedProtocol, "elapsed_ms": time.Since(started).Milliseconds()}
			if err != nil {
				fields["error"] = diagnosticError(err)
			}
			entry.WithFields(fields).Trace("MITM upstream TLS handshake finished")
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			fields := log.Fields{"event": "mitm_upstream_written", "elapsed_ms": time.Since(started).Milliseconds()}
			if info.Err != nil {
				fields["error"] = diagnosticError(info.Err)
			}
			entry.WithFields(fields).Trace("MITM upstream request written")
		},
		GotFirstResponseByte: func() {
			entry.WithFields(log.Fields{"event": "mitm_upstream_first_byte", "elapsed_ms": time.Since(started).Milliseconds()}).Trace("MITM upstream first response byte")
		},
	}
	return r.WithContext(httptrace.WithClientTrace(r.Context(), trace))
}
