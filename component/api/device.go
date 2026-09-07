// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"
	"net/netip"
)

func (s *server) serveDevice(w http.ResponseWriter, r *http.Request, resolve func(netip.Addr) ([6]byte, error)) {
	if !apiBody(w, r, nil) {
		return
	}
	ip, mac, ok := apiDevice(w, r, resolve)
	if !ok {
		return
	}
	writeAPI(w, s.options.Devices.DeviceState(ip, mac))
}

func (s *server) serveClientSet(w http.ResponseWriter, r *http.Request, resolve func(netip.Addr) ([6]byte, error)) {
	if !apiBody(w, r, nil) {
		return
	}
	name := r.PathValue("name")
	if !s.options.Devices.HasClientSet(name) {
		apiError(w, 404, "client set not found")
		return
	}
	ip, mac, ok := apiDevice(w, r, resolve)
	if !ok {
		return
	}
	state, err := s.options.Devices.UpdateClientSet(name, ip, mac, r.Method == http.MethodPut)
	if err != nil {
		apiSaveError(w, err)
		return
	}
	writeAPI(w, state)
}

func (s *server) serveMITM(w http.ResponseWriter, r *http.Request, resolve func(netip.Addr) ([6]byte, error)) {
	if s.options.Certificates == nil {
		apiError(w, 404, "HTTPS modules are disabled")
		return
	}
	fingerprint := r.Header.Get("X-Dae-MITM")
	if fingerprint == "" {
		apiError(w, 403, "MITM changes require X-Dae-MITM containing the CA SHA-256 fingerprint")
		return
	}
	if fingerprint != s.options.Certificates.Fingerprint {
		apiError(w, 409, "the CA certificate changed; reload the page and verify the certificate")
		return
	}
	var enabled *bool
	if r.Method == http.MethodPut {
		var request struct {
			Enabled *bool `json:"enabled"`
		}
		if !apiBody(w, r, &request) {
			return
		}
		if request.Enabled == nil {
			apiError(w, 400, `expected {"enabled":true} or {"enabled":false}`)
			return
		}
		enabled = request.Enabled
	} else if !apiBody(w, r, nil) {
		return
	}
	ip, mac, ok := apiDevice(w, r, resolve)
	if !ok {
		return
	}
	state, err := s.options.Devices.UpdateMITM(ip, mac, enabled)
	if err != nil {
		apiSaveError(w, err)
		return
	}
	writeAPI(w, state)
}
