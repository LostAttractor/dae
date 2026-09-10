// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/component/mitm/plugin"
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
	chain := h.chain(flow, func(e *plugin.Exchange) (*http.Response, error) { return transport.RoundTrip(e.Request) })
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		defer controller.SetReadDeadline(time.Time{})
		exchange := &plugin.Exchange{Client: client, SetReadDeadline: controller.SetReadDeadline}
		defer func() {
			if exchange.Request != nil {
				_ = exchange.Close()
			}
		}()
		proxy := &httputil.ReverseProxy{
			Director: func(req *http.Request) { req.RemoteAddr = "" },
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				exchange.Request = req
				response, err := chain(exchange)
				_ = controller.SetReadDeadline(time.Time{})
				if err != nil {
					return nil, err
				}
				response.Request = req
				return response, nil
			}),
			ModifyResponse: func(response *http.Response) error {
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
				status := http.StatusBadGateway
				var failure *plugin.HTTPError
				if errors.As(err, &failure) {
					status = failure.Status
				}
				http.Error(w, "MITM upstream processing failed", status)
			}, ErrorLog: log.New(logWriter{h}, "", 0),
		}
		proxy.ServeHTTP(w, r)
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

type logWriter struct{ host *Host }

func (w logWriter) Write(p []byte) (int, error) {
	if w.host.options.Log != nil {
		w.host.options.Log(string(p))
	}
	return len(p), nil
}
