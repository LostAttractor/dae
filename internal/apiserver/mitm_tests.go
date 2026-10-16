// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"net"
	"net/http"
	"net/netip"

	"github.com/daeuniverse/dae/api"
)

type MITMTestStore interface {
	Start(netip.Addr, [6]byte, netip.AddrPort, string, bool) (api.MITMTest, error)
	Get(string, netip.Addr, [6]byte) (api.MITMTest, bool)
}

func (s *handler) serveMITMTest(w http.ResponseWriter, r *http.Request, who caller) {
	if !apiBody(w, r, nil) {
		return
	}
	ip, mac := who.ip, who.identity.MAC
	if s.options.MITMTests == nil {
		apiError(w, http.StatusNotFound, "MITM tests are unavailable")
		return
	}
	if r.Method == http.MethodPost {
		local, ok := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)
		if !ok {
			apiError(w, http.StatusForbidden, "MITM tests require a direct LAN connection")
			return
		}
		device := s.options.Devices.DeviceState(ip, mac)
		test, err := s.options.MITMTests.Start(ip, mac, local.AddrPort(), requestOrigin(r), device.MITM != nil && device.MITM.Enabled)
		if err != nil {
			apiError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		writeAPIStatus(w, test, http.StatusCreated)
		return
	}
	test, found := s.options.MITMTests.Get(r.PathValue("id"), ip, mac)
	if !found {
		apiError(w, http.StatusNotFound, "test expired, configuration changed, or test belongs to another device")
		return
	}
	writeAPI(w, test)
}
