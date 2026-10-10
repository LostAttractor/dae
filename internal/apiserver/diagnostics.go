// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/daeuniverse/dae/api"
)

type DiagnosticStore interface {
	Explain(context.Context, api.ExplainRequest, bool) (*api.ExplainResponse, error)
	DiagnosticDeviceContext(api.DiagnosticContext) api.DeviceContext
	ClientGroups() api.ClientGroups
	ManagedDevice([6]byte) api.ManagedDevice
	UpdateManagedMembership(string, [6]byte, bool) (api.ClientGroup, error)
	UpdateManagedMITM([6]byte, *bool) (api.ManagedDevice, error)
	ClientImpact(context.Context, string, api.ClientImpactRequest, bool) (*api.ClientImpact, error)
}

func (s *handler) diagnosticsAvailable(w http.ResponseWriter) bool {
	if s.options.Diagnostics == nil {
		apiError(w, 503, "diagnostics unavailable")
		return false
	}
	return true
}

func (s *handler) inheritDiagnosticContext(w http.ResponseWriter, r *http.Request, target *api.DiagnosticContext) bool {
	if target.SourceIP != "" || target.MAC != "" || target.IfIndex != nil || target.PhysicalIfIndex != nil || target.Interface != "" || target.Policy != "" || target.ProcessName != nil || target.Origin != "" && target.Origin != "lan" {
		apiError(w, 400, "device diagnostics inherit identity; use the administrator endpoint to override it")
		return false
	}
	ip, mac, ok := apiDevice(w, r, s.options.ResolveClient)
	if !ok {
		return false
	}
	inherited := api.DiagnosticContext{Origin: "lan", SourceIP: ip.WithZone("").String(), MAC: net.HardwareAddr(mac[:]).String()}
	if s.options.ResolveContext != nil {
		source, _ := netip.ParseAddrPort(r.RemoteAddr)
		local := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr).AddrPort()
		var err error
		inherited, err = s.options.ResolveContext(source, local)
		if err != nil {
			apiError(w, 403, "cannot inherit verified ingress: "+err.Error())
			return false
		}
	}
	inherited.SourcePort, inherited.DSCP, inherited.Mark = target.SourcePort, target.DSCP, target.Mark
	*target = inherited
	return true
}

func (s *handler) serveDiagnosticContext(w http.ResponseWriter, r *http.Request) {
	if !s.diagnosticsAvailable(w) || !apiBody(w, r, nil) {
		return
	}
	var input api.DiagnosticContext
	if !s.inheritDiagnosticContext(w, r, &input) {
		return
	}
	writeAPI(w, s.options.Diagnostics.DiagnosticDeviceContext(input))
}

func (s *handler) serveExplain(w http.ResponseWriter, r *http.Request) {
	self := strings.HasPrefix(r.URL.Path, "/api/device/")
	if !self {
		if _, ok := s.requireAdmin(w, r); !ok {
			return
		}
	}
	if !s.diagnosticsAvailable(w) {
		return
	}
	var request api.ExplainRequest
	if !apiBodyLimit(w, r, &request, 64<<10) {
		return
	}
	if self && !s.inheritDiagnosticContext(w, r, &request.Context) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	response, err := s.options.Diagnostics.Explain(ctx, request, self)
	if err != nil {
		apiError(w, 400, err.Error())
		return
	}
	writeAPI(w, response)
}

func managedMAC(w http.ResponseWriter, r *http.Request) ([6]byte, bool) {
	parsed, err := net.ParseMAC(r.PathValue("mac"))
	if err != nil || len(parsed) != 6 || parsed[0]&1 != 0 || [6]byte(parsed) == [6]byte{} {
		apiError(w, 400, "expected a nonzero unicast Ethernet MAC")
		return [6]byte{}, false
	}
	return [6]byte(parsed), true
}

func (s *handler) serveClients(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	if !s.diagnosticsAvailable(w) || !apiBody(w, r, nil) {
		return
	}
	groups := s.options.Diagnostics.ClientGroups()
	if name := r.PathValue("name"); name != "" {
		for _, group := range groups.Groups {
			if group.Name == name {
				writeAPI(w, group)
				return
			}
		}
		apiError(w, 404, "client set not found")
		return
	}
	writeAPI(w, groups)
}

func (s *handler) serveManagedDevice(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	if !s.diagnosticsAvailable(w) || !apiBody(w, r, nil) {
		return
	}
	mac, ok := managedMAC(w, r)
	if !ok {
		return
	}
	writeAPI(w, s.options.Diagnostics.ManagedDevice(mac))
}

func (s *handler) serveManagedMembership(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	if !s.diagnosticsAvailable(w) || !apiBody(w, r, nil) {
		return
	}
	mac, ok := managedMAC(w, r)
	if !ok {
		return
	}
	if !s.options.Devices.HasClientSet(r.PathValue("name")) {
		apiError(w, 404, "client set not found")
		return
	}
	state, err := s.options.Diagnostics.UpdateManagedMembership(r.PathValue("name"), mac, r.Method == http.MethodPut)
	if err != nil {
		apiSaveError(w, err)
		return
	}
	writeAPI(w, state)
}

func (s *handler) serveManagedMITM(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	if !s.diagnosticsAvailable(w) {
		return
	}
	mac, ok := managedMAC(w, r)
	if !ok {
		return
	}
	if s.options.Certificates == nil {
		apiError(w, 404, "HTTPS modules are disabled")
		return
	}
	if r.Header.Get("X-Dae-MITM") != s.options.Certificates.Identity.Fingerprint {
		apiError(w, 409, "MITM changes require the current CA fingerprint in X-Dae-MITM")
		return
	}
	var enabled *bool
	if r.Method == http.MethodPut {
		var request api.SetMITMRequest
		if !apiBody(w, r, &request) {
			return
		}
		if request.Enabled == nil {
			apiError(w, 400, "enabled is required")
			return
		}
		enabled = request.Enabled
	} else if !apiBody(w, r, nil) {
		return
	}
	state, err := s.options.Diagnostics.UpdateManagedMITM(mac, enabled)
	if err != nil {
		apiSaveError(w, err)
		return
	}
	writeAPI(w, state)
}

func (s *handler) serveClientImpact(w http.ResponseWriter, r *http.Request) {
	self := strings.HasPrefix(r.URL.Path, "/api/device/")
	if !self {
		if _, ok := s.requireAdmin(w, r); !ok {
			return
		}
	}
	if !s.diagnosticsAvailable(w) {
		return
	}
	name := r.PathValue("name")
	if !s.options.Devices.HasClientSet(name) {
		apiError(w, 404, "client set not found")
		return
	}
	var request api.ClientImpactRequest
	if !apiBodyLimit(w, r, &request, 64<<10) {
		return
	}
	if request.Joined == nil {
		apiError(w, 400, "joined is required")
		return
	}
	if self && !s.inheritDiagnosticContext(w, r, &request.Context) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	response, err := s.options.Diagnostics.ClientImpact(ctx, name, request, self)
	if err != nil {
		apiError(w, 400, fmt.Sprint(err))
		return
	}
	writeAPI(w, response)
}
