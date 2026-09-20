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
	"net/netip"
	"net/url"
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
	transport := h.plannedTransport(plan, false)
	return h.handlerForFlow(scheme, flow, transport, &http.Client{Transport: transport}), transport.close
}

// The intercepted protocol and auxiliary plugin requests can use different
// transports. Both plan the final request before looking up a connection.
func (h *Host) handlerForFlow(scheme string, flow plugin.Flow, transport http.RoundTripper, client *http.Client) http.Handler {
	host, port := flow.Host, flow.Port
	chain := h.chain(flow, func(e *plugin.Exchange) (*http.Response, error) {
		return h.roundTrip(transport, e.Request)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// HTTP/3 replaces the server request Trailer map at EOF.
		source := r
		h.mu.Lock()
		if h.closed {
			h.mu.Unlock()
			http.Error(w, "MITM is draining", http.StatusServiceUnavailable)
			return
		}
		h.requests.Add(1)
		h.mu.Unlock()
		defer h.requests.Done()
		ctx, cancel := context.WithCancel(r.Context())
		stop := context.AfterFunc(h.forceContext, cancel)
		defer func() { stop(); cancel() }()
		r = r.WithContext(ctx)
		if r.Method == http.MethodConnect {
			http.Error(w, "CONNECT is not supported on the transparent listener", 405)
			return
		}
		if !sameAuthority(r.Host, host, port, scheme) {
			http.Error(w, "Request authority differs from intercepted destination", 421)
			return
		}
		r.URL.Scheme, r.URL.Host = scheme, r.Host
		r.RequestURI = ""
		connection, _ := plugin.IDs(r.Context())
		r = r.WithContext(plugin.WithIDs(r.Context(), connection, strconv.FormatUint(serial.Add(1), 10)))
		controller := http.NewResponseController(w)
		if r.ProtoMajor == 1 {
			// Forward uploads and early responses concurrently.
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
			Director: func(*http.Request) {},
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				exchange.Request = req
				forwardRequestTrailers(req, source)
				response, err := chain(exchange)
				_ = controller.SetReadDeadline(time.Time{})
				if err != nil {
					return nil, err
				}
				response.Request = req
				return response, nil
			}),
			ModifyResponse: func(response *http.Response) error {
				// Prevent net/http from inventing an absent Content-Type.
				if len(response.Header["Content-Type"]) == 0 {
					w.Header()["Content-Type"] = nil
				}
				if len(response.Trailer) > 0 {
					response.Header.Del("Content-Length")
					response.ContentLength = -1
				}
				h.filterAltSvc(response.Header, scheme, flow)
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
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
			}, ErrorLog: log.New(logWriter{h.options.Logger, logrus.TraceLevel}, "", 0),
		}
		// ReverseProxy derives X-Forwarded-For from its incoming request.
		incoming := r.WithContext(r.Context())
		incoming.RemoteAddr = ""
		proxy.ServeHTTP(w, incoming)
	})
}

func sameAuthority(authority, host string, port uint16, scheme string) bool {
	u, err := url.Parse(scheme + "://" + authority)
	if err != nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	p := u.Port()
	if p == "" {
		p = "80"
		if scheme == "https" {
			p = "443"
		}
	}
	requestedPort, err := strconv.ParseUint(p, 10, 16)
	if err != nil || requestedPort != uint64(port) {
		return false
	}
	if target, err := netip.ParseAddr(host); err == nil {
		requested, err := netip.ParseAddr(u.Hostname())
		return err == nil && requested.Unmap() == target.Unmap()
	}
	return strings.EqualFold(strings.TrimSuffix(u.Hostname(), "."), strings.TrimSuffix(host, "."))
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
