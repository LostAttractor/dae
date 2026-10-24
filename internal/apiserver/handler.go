// SPDX-License-Identifier: AGPL-3.0-only
package apiserver

import (
	"net/http"
	"net/netip"
	"slices"
	"strings"

	contract "github.com/daeuniverse/dae/api"
)

type Certificates struct {
	Identity contract.Certificate
	Handler  http.Handler
}

// ClientResolver receives the actual TCP endpoints, including IPv6 zones.
type ClientResolver func(source, destination netip.AddrPort) (contract.ClientIdentity, error)

// Options captures one plane's configuration. Publish a new handler when
// configuration changes; stores continue to provide live runtime state.
// Status, Selectors, Probes, Devices and ResolveClient are required dependencies.
type Options struct {
	Status            func() *contract.StatusSnapshot
	Selectors         SelectorStore
	Probes            ProbeStore
	Scripts           ScriptStore
	ScriptStorage     ScriptStoreMigrator
	Operations        OperationStore
	Devices           DeviceStore
	DeviceStatus      func(netip.Addr, [6]byte) contract.DeviceStatus
	ResolveClient     ClientResolver
	Certificates      *Certificates
	MITMTests         MITMTestStore
	Diagnostics       DiagnosticStore
	UserKey           string
	AdminKey          string
	AllowLANAnonymous bool
	WebOrigins        []string
	Metrics           http.Handler
	Pprof             bool
}

type Handler struct {
	options  Options
	routes   http.Handler
	policies map[string]accessPolicy
}

// LocalServices configures daemon-owned routes served on the local Unix socket
// without holding or requiring a control plane.
type LocalServices struct {
	Operations OperationStore
	Metrics    http.Handler
	Pprof      bool
}

func newLocalHandler(services LocalServices) *Handler {
	s := &Handler{options: Options{Operations: services.Operations, Metrics: services.Metrics, Pprof: services.Pprof}}
	mux := http.NewServeMux()
	s.registerOperationRoutes(mux)
	s.routes = mux
	return s
}

func (s *Handler) registerOperationRoutes(mux *http.ServeMux) {
	s.route(mux, "POST /api/resources/refresh", accessAdmin, s.serveResources)
	s.route(mux, "GET /api/resources", accessAdmin, s.serveResources)
	s.route(mux, "POST /api/operations", accessAdmin, s.serveOperations)
	s.route(mux, "GET /api/operations/{id}", accessAdmin, s.serveOperations)
}

type webHandler struct {
	*Handler
	web http.Handler
}

func (h webHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") || monitoringPath(r.URL.Path) {
		h.Handler.ServeHTTP(w, r)
		return
	}
	h.web.ServeHTTP(w, r)
}

// WithWeb serves API and monitoring routes through s and delegates all other paths
// to web while keeping monitoring preparation directly available to Server.
func (s *Handler) WithWeb(web http.Handler) http.Handler {
	if web == nil {
		return s
	}
	return webHandler{Handler: s, web: web}
}

// NewHandler serves one plane's management API. The owner drains requests before
// closing that plane and publishing its replacement.
func NewHandler(options Options) *Handler {
	s := &Handler{options: options}
	mux := http.NewServeMux()
	s.route(mux, "PUT /api/session", accessLogin, s.serveLogin)
	s.route(mux, "DELETE /api/session", accessPublic, serveLogout)
	s.route(mux, "GET /api/status", accessUser, func(w http.ResponseWriter, r *http.Request, who caller) {
		if apiBody(w, r, nil) {
			snapshot := *options.Status()
			if who.role != roleAdmin {
				// Plugin reports can contain private script output; preserve the shared snapshot.
				snapshot.Plugins = slices.Clone(snapshot.Plugins)
				for i := range snapshot.Plugins {
					snapshot.Plugins[i].Details = nil
				}
			}
			writeAPI(w, &snapshot)
		}
	})
	if options.Certificates != nil {
		s.route(mux, "POST /api/certificate/tests", accessUser|accessDirect|accessBootstrap, s.serveCertificateTest)
		s.route(mux, "GET /api/certificate/tests/{id}", accessPublic|accessDirect|accessBootstrap, s.serveCertificateTest)
		certificates := options.Certificates.Handler
		s.route(mux, "GET /api/certificate", accessUser|accessBootstrap, func(w http.ResponseWriter, r *http.Request, _ caller) {
			if apiBody(w, r, nil) {
				writeAPI(w, options.Certificates.Identity)
			}
		})
		for _, path := range []string{"/api/certificate/ca.pem", "/api/certificate/ca.cer", "/api/certificate/ca.mobileconfig"} {
			s.route(mux, "GET "+path, accessUser|accessBootstrap, func(w http.ResponseWriter, r *http.Request, _ caller) {
				copy := r.Clone(r.Context())
				copy.URL = r.URL.Clone()
				copy.URL.Path = strings.TrimPrefix(r.URL.Path, "/api/certificate")
				certificates.ServeHTTP(w, copy)
			})
		}
	}
	s.route(mux, "GET /api/selectors", accessUser, s.serveSelectors)
	s.route(mux, "PUT /api/selectors/{group}", accessAdmin, s.serveSelector)
	s.route(mux, "DELETE /api/selectors/{group}", accessAdmin, s.serveSelector)
	s.route(mux, "POST /api/probes", accessAdmin, s.serveProbe)
	s.route(mux, "POST /api/plugins/{instance}/scripts/run", accessAdmin, s.serveScript)
	s.route(mux, "POST /api/plugins/{instance}/store/migrate", accessAdmin, s.serveScriptStoreMigration)
	s.registerOperationRoutes(mux)
	s.route(mux, "GET /api/device", accessDevice, s.serveDevice)
	s.route(mux, "GET /api/device/status", accessDevice, s.serveDeviceStatus)
	s.route(mux, "GET /api/device/context", accessLAN, s.serveDiagnosticContext)
	s.route(mux, "POST /api/device/diagnostics/explain", accessAdmin|accessLAN, s.serveExplain)
	s.route(mux, "POST /api/diagnostics/explain", accessAdmin, s.serveExplain)
	s.route(mux, "POST /api/device/sets/{name}/impact", accessAdmin|accessDevice, s.serveClientImpact)
	s.route(mux, "POST /api/clients/{name}/impact", accessAdmin, s.serveClientImpact)
	s.route(mux, "GET /api/clients", accessAdmin, s.serveClients)
	s.route(mux, "GET /api/clients/{name}", accessAdmin, s.serveClients)
	s.route(mux, "GET /api/devices/{mac}", accessAdmin, s.serveManagedDevice)
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		s.route(mux, method+" /api/clients/{name}/members/{mac}", accessAdmin, s.serveManagedMembership)
		s.route(mux, method+" /api/devices/{mac}/mitm", accessAdmin, s.serveManagedMITM)
	}
	s.route(mux, "POST /api/device/mitm-tests", accessDevice, s.serveMITMTest)
	s.route(mux, "GET /api/device/mitm-tests/{id}", accessDevice, s.serveMITMTest)
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		s.route(mux, method+" /api/device/sets/{name}", accessDevice, s.serveClientSet)
		s.route(mux, method+" /api/device/mitm", accessDevice, s.serveMITM)
	}
	s.routes = mux
	return s
}

func (s *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if target, matched := s.PrepareMonitoring(w, r); matched {
		if target != nil {
			target.ServeHTTP(w, r)
		}
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if !s.prepareRequest(w, r) {
		return
	}
	if r.Method == http.MethodOptions {
		s.preflight(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		if r.URL.RawQuery != "" {
			apiError(w, 400, "API requests do not accept query parameters")
			return
		}
	}
	s.routes.ServeHTTP(w, r)
}
