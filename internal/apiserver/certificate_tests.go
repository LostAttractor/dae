// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"net"
	"net/http"
	"net/netip"

	"github.com/daeuniverse/dae/api"
)

type CertificateTestStore interface {
	Start(netip.Addr, [6]byte, netip.AddrPort, bool) (api.CertificateTest, error)
	Get(string, netip.Addr, [6]byte) (api.CertificateTest, bool)
}

func (s *handler) serveCertificateTest(w http.ResponseWriter, r *http.Request) {
	if !apiBody(w, r, nil) {
		return
	}
	ip, mac, ok := apiDevice(w, r, s.options.ResolveClient)
	if !ok {
		return
	}
	if s.options.CertificateTests == nil {
		apiError(w, http.StatusNotFound, "certificate tests are unavailable")
		return
	}
	if r.Method == http.MethodPost {
		local, ok := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)
		if !ok {
			apiError(w, http.StatusForbidden, "certificate tests require a direct LAN connection")
			return
		}
		device := s.options.Devices.DeviceState(ip, mac)
		test, err := s.options.CertificateTests.Start(ip, mac, local.AddrPort(), device.MITM != nil && device.MITM.Enabled)
		if err != nil {
			apiError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		writeAPIStatus(w, test, http.StatusCreated)
		return
	}
	test, found := s.options.CertificateTests.Get(r.PathValue("id"), ip, mac)
	if !found {
		apiError(w, http.StatusNotFound, "test expired, configuration changed, or test belongs to another device")
		return
	}
	writeAPI(w, test)
}
