// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/component/plugin"
	logrus "github.com/sirupsen/logrus"
)

var serial atomic.Uint64

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Handler has a connection-local transport pool: different original flows,
// destinations, outbound policies and TLS identities cannot share its sockets.
func (h *Host) Handler(scheme, host string, port uint16, plan UpstreamPlanner) (http.Handler, func()) {
	return h.HandlerForFlow(scheme, plugin.Flow{Host: host, Port: port}, plan)
}

func (h *Host) HandlerForFlow(scheme string, flow plugin.Flow, plan UpstreamPlanner) (http.Handler, func()) {
	transport := h.connectionTransport(scheme, flow, plan, false)
	client, closeClient := h.RoutedHTTPClient(plan)
	return h.handlerForFlow(scheme, flow, transport, client), func() {
		transport.close()
		closeClient()
	}
}

// The intercepted protocol and auxiliary plugin requests can use different
// transports. Forwarding binds unchanged URL targets to the original ingress;
// auxiliary requests are independently routed using their own URLs.
func (h *Host) handlerForFlow(scheme string, flow plugin.Flow, transport http.RoundTripper, client *http.Client) http.Handler {
	host := flow.Host
	chainFor := h.chainsForFlow(flow, func(incoming plugin.Flow) plugin.Handler {
		return func(e *plugin.Exchange) (*http.Response, error) {
			request := upstreamRequest(e.Request, scheme, incoming, flow)
			return h.roundTrip(transport, request)
		}
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Keep the server's request: HTTP/3 replaces its Trailer map at EOF,
		// so even a WithContext copy cannot observe the final trailers.
		source := r
		ctx, cancel := context.WithCancel(r.Context())
		stop := context.AfterFunc(h.forceContext, cancel)
		defer func() { stop(); cancel() }()
		connection, _ := plugin.IDs(ctx)
		r = r.WithContext(plugin.WithIDs(ctx, connection, strconv.FormatUint(serial.Add(1), 10)))
		observation := h.observeRequest(w, r, scheme, flow)
		if observation != nil {
			w = observation.writer
			defer func() {
				failure := recover()
				observation.finish(r, failure)
				if failure != nil {
					panic(failure)
				}
			}()
		}
		h.mu.Lock()
		if h.closed {
			h.mu.Unlock()
			http.Error(w, "MITM is draining", http.StatusServiceUnavailable)
			return
		}
		h.requests.Add(1)
		h.mu.Unlock()
		defer h.requests.Done()
		if r.Method == http.MethodConnect {
			http.Error(w, "CONNECT is not supported on the transparent listener", 405)
			return
		}
		requestFlow, reason := admitRequestAuthority(r, scheme, flow)
		if reason != "" {
			if observation != nil {
				observation.authorityRejected(reason)
			}
			http.Error(w, "Request target differs from intercepted connection", 421)
			return
		}
		chain := chainFor(requestFlow)
		scoped := h.Match(requestFlow.Host, requestFlow.Port) != HTTPBypass
		if observation != nil && requestFlow.Host != flow.Host {
			observation.logger.WithFields(logrus.Fields{"event": "mitm_authority_coalesced", "plugin_scope": scoped}).Trace("MITM accepted alternate request authority")
		}
		r.URL.Scheme, r.URL.Host = scheme, r.Host
		r.RequestURI = ""
		controller := http.NewResponseController(w)
		if r.ProtoMajor == 1 {
			// Upload and response forwarding run concurrently. The HTTP/1
			// server must not drain the upload before sending an early response.
			_ = controller.EnableFullDuplex()
		}
		defer controller.SetReadDeadline(time.Time{})
		exchange := &plugin.Exchange{Request: r, Client: client, SetReadDeadline: controller.SetReadDeadline}
		defer func() {
			if exchange.Request.Body != nil {
				_ = exchange.Request.Body.Close()
			}
		}()
		proxy := &httputil.ReverseProxy{
			// The destination is already set. Director preserves forwarding
			// headers and the raw query; request preparation can fail in RoundTrip.
			Director: func(*http.Request) {},
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				exchange.Request = req
				forwardRequestTrailers(req, source)
				response, err := chain(exchange)
				_ = controller.SetReadDeadline(time.Time{})
				if err != nil {
					return nil, err
				}
				// Also associate responses for authorities without plugin hooks.
				response.Request = req
				return response, nil
			}),
			ModifyResponse: func(response *http.Response) error {
				// A missing upstream type must remain missing. Set the writer's
				// sentinel: ReverseProxy does not copy nil-valued header entries.
				if len(response.Header["Content-Type"]) == 0 {
					w.Header()["Content-Type"] = nil
				}
				if observation != nil {
					observation.observeResponse(response)
				}
				if len(response.Trailer) > 0 {
					response.Header.Del("Content-Length")
					response.ContentLength = -1
				}
				if requestFlow.Host == flow.Host || scoped {
					h.filterAltSvc(response.Header, scheme, requestFlow)
				}
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				if observation != nil {
					observation.processingError = err
				}
				if errors.Is(err, plugin.ErrAbort) {
					panic(http.ErrAbortHandler)
				}
				if r.Context().Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
					connection, request := plugin.IDs(r.Context())
					h.options.Logger.WithFields(logrus.Fields{
						"connection_id": connection, "request_id": request, "host": host, "method": r.Method,
					}).WithError(resource.RedactError(err)).Trace("MITM request failed")
				}
				status := http.StatusBadGateway
				if failure, ok := errors.AsType[*plugin.HTTPError](err); ok {
					status = failure.Status
				}
				http.Error(w, "MITM upstream processing failed", status)
			}, ErrorLog: log.New(logWriter{h.requestLogger(r), logrus.TraceLevel}, "", 0),
		}
		// ReverseProxy derives X-Forwarded-For from its incoming request, not
		// the Director's copy. Transparent forwarding must not append our
		// client's address or change an existing forwarding header.
		incoming := r.WithContext(r.Context())
		incoming.RemoteAddr = ""
		proxy.ServeHTTP(w, incoming)
	})
}

type logWriter struct {
	logger *logrus.Entry
	level  logrus.Level
}

func (w logWriter) Write(p []byte) (int, error) {
	message := strings.TrimSpace(string(p))
	level := w.level
	// net/http also sends recovered handler panics through ErrorLog. Keep
	// those visible while ordinary client and stream errors stay diagnostic.
	if strings.HasPrefix(message, "http: panic serving ") || strings.HasPrefix(message, "http2: panic serving ") {
		level = logrus.ErrorLevel
	}
	w.logger.Log(level, resource.RedactText(message))
	return len(p), nil
}
