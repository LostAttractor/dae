// SPDX-License-Identifier: AGPL-3.0-only
package apiserver

import (
	"net/http"
	"net/netip"
	"strings"

	contract "github.com/daeuniverse/dae/api"
)

type Certificates struct {
	Identity contract.Certificate
	Handler  http.Handler
}

// ClientResolver receives the actual TCP endpoints, including IPv6 zones.
type ClientResolver func(source, destination netip.AddrPort) (ClientIdentity, error)

// ClientIdentity is verified ingress evidence. IP links have no device MAC.
type ClientIdentity struct {
	LinkType        string
	MAC             [6]byte
	IfIndex         uint32
	PhysicalIfIndex uint32
}

// Options captures one plane's configuration. Publish a new handler when
// configuration changes; stores continue to provide live runtime state.
// Status, Selectors, Probes, Devices and ResolveClient are required dependencies.
type Options struct {
	Status           func() *contract.StatusSnapshot
	Selectors        SelectorStore
	Probes           ProbeStore
	Scripts          ScriptStore
	Operations       OperationStore
	Devices          DeviceStore
	DeviceStatus     func(netip.Addr, [6]byte) contract.DeviceStatus
	ResolveClient    ClientResolver
	Certificates     *Certificates
	CertificateTests CertificateTestStore
	Diagnostics      DiagnosticStore
	APIKey           string
}

type handler struct{ options Options }

// NewHandler serves one plane's management API. The owner drains requests before
// closing that plane and publishing its replacement.
func NewHandler(options Options) http.Handler {
	s := &handler{options: options}
	mux := http.NewServeMux()
	s.route(mux, "PUT /api/session", accessLogin, s.serveLogin)
	s.route(mux, "DELETE /api/session", accessPublic, serveLogout)
	s.route(mux, "GET /api/status", accessAdmin, func(w http.ResponseWriter, r *http.Request, _ caller) {
		if apiBody(w, r, nil) {
			writeAPI(w, options.Status())
		}
	})
	if options.Certificates != nil {
		certificates := options.Certificates.Handler
		s.route(mux, "GET /api/certificate", accessPublic, func(w http.ResponseWriter, r *http.Request, _ caller) {
			if apiBody(w, r, nil) {
				writeAPI(w, options.Certificates.Identity)
			}
		})
		for _, path := range []string{"/ca.pem", "/ca.cer", "/ca.mobileconfig"} {
			s.route(mux, "GET "+path, accessPublic, func(w http.ResponseWriter, r *http.Request, _ caller) {
				certificates.ServeHTTP(w, r)
			})
		}
	}
	s.route(mux, "GET /api/selectors", accessAdmin, s.serveSelectors)
	s.route(mux, "PUT /api/selectors/{group}", accessAdmin, s.serveSelector)
	s.route(mux, "DELETE /api/selectors/{group}", accessAdmin, s.serveSelector)
	s.route(mux, "POST /api/probes", accessAdmin, s.serveProbe)
	s.route(mux, "POST /api/plugins/{instance}/scripts/run", accessAdmin, s.serveScript)
	s.route(mux, "POST /api/resources/refresh", accessAdmin, s.serveResources)
	s.route(mux, "GET /api/resources", accessAdmin, s.serveResources)
	s.route(mux, "POST /api/operations", accessAdmin, s.serveOperations)
	s.route(mux, "GET /api/operations/{id}", accessAdmin, s.serveOperations)
	s.route(mux, "GET /api/device", accessDevice, s.serveDevice)
	s.route(mux, "GET /api/device/status", accessDevice, s.serveDeviceStatus)
	s.route(mux, "GET /api/device/context", accessLAN, s.serveDiagnosticContext)
	s.route(mux, "POST /api/device/diagnostics/explain", accessLAN, s.serveExplain)
	s.route(mux, "POST /api/diagnostics/explain", accessAdmin, s.serveExplain)
	s.route(mux, "POST /api/device/sets/{name}/impact", accessDevice, s.serveClientImpact)
	s.route(mux, "POST /api/clients/{name}/impact", accessAdmin, s.serveClientImpact)
	s.route(mux, "GET /api/clients", accessAdmin, s.serveClients)
	s.route(mux, "GET /api/clients/{name}", accessAdmin, s.serveClients)
	s.route(mux, "GET /api/devices/{mac}", accessAdmin, s.serveManagedDevice)
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		s.route(mux, method+" /api/clients/{name}/members/{mac}", accessAdmin, s.serveManagedMembership)
		s.route(mux, method+" /api/devices/{mac}/mitm", accessAdmin, s.serveManagedMITM)
	}
	s.route(mux, "POST /api/device/certificate-tests", accessDevice, s.serveCertificateTest)
	s.route(mux, "GET /api/device/certificate-tests/{id}", accessDevice, s.serveCertificateTest)
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		s.route(mux, method+" /api/device/sets/{name}", accessDevice, s.serveClientSet)
		s.route(mux, method+" /api/device/mitm", accessDevice, s.serveMITM)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if (!localAPISocket(r) && !localIPHost(r)) || !sameOrigin(r) {
				apiError(w, 403, "open the API directly using the router IP address and port; cross-origin access is not allowed")
				return
			}
			if r.URL.RawQuery != "" {
				apiError(w, 400, "API requests do not accept query parameters")
				return
			}
			if (r.Method == http.MethodPut || r.Method == http.MethodDelete || r.Method == http.MethodPost) && r.Header.Get("X-Dae-API") != "1" {
				apiError(w, 403, "changes require X-Dae-API: 1")
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}
