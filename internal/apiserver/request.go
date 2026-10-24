// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	jsonv1 "encoding/json"
	json "encoding/json/v2"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/daeuniverse/dae/api"
	log "github.com/sirupsen/logrus"
)

// Requiring the connected listener's literal IP prevents a hostile domain from
// rebinding to this LAN service and issuing apparently same-origin requests.
func localIPHost(r *http.Request) bool {
	host, err := netip.ParseAddrPort(r.Host)
	if err != nil {
		literal := r.Host
		if strings.HasPrefix(literal, "[") && strings.HasSuffix(literal, "]") {
			literal = literal[1 : len(literal)-1]
		}
		ip, err := netip.ParseAddr(literal)
		if err != nil {
			return false
		}
		port := uint16(80)
		if r.TLS != nil {
			port = 443
		}
		host = netip.AddrPortFrom(ip, port)
	}
	local, ok := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)
	if !ok {
		return false
	}
	address := local.AddrPort()
	return address.Port() == host.Port() &&
		address.Addr().Unmap().WithZone("") == host.Addr().Unmap().WithZone("")
}

func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	origins := r.Header.Values("Origin")
	if len(origins) == 0 {
		return true
	}
	if len(origins) != 1 {
		return false
	}
	origin, err := api.NormalizeOrigin(origins[0])
	if err != nil {
		return false
	}
	local, err := api.NormalizeOrigin(requestScheme(r) + "://" + r.Host)
	return err == nil && origin == local
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func requestOrigin(r *http.Request) string {
	if validOrigin(r) {
		origin, _ := api.NormalizeOrigin(r.Header.Get("Origin"))
		return origin
	}
	origin, _ := api.NormalizeOrigin(requestScheme(r) + "://" + r.Host)
	return origin
}

func apiError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, map[string]string{"error": message})
}

// A nil destination requires an empty body (membership changes and deletes).
func apiBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	return apiBodyLimit(w, r, dst, 1024)
}

func apiBodyLimit(w http.ResponseWriter, r *http.Request, dst any, limit int64) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		apiError(w, 413, "request body exceeds endpoint limit or cannot be read")
		return false
	}
	if dst == nil {
		if len(body) != 0 {
			apiError(w, 400, "this request does not accept a body")
			return false
		}
		return true
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		apiError(w, 415, "request requires application/json")
		return false
	}
	if err := json.Unmarshal(body, dst, json.RejectUnknownMembers(true)); err != nil {
		apiError(w, 400, "invalid JSON request: "+err.Error())
		return false
	}
	return true
}

func apiClient(w http.ResponseWriter, r *http.Request, resolve ClientResolver) (netip.Addr, api.ClientIdentity, bool) {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		apiError(w, 400, "cannot read the connection source address")
		return netip.Addr{}, api.ClientIdentity{}, false
	}
	ip := peer.Addr().Unmap()
	local, ok := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)
	if !ok {
		apiError(w, 400, "cannot read the connection destination address")
		return ip, api.ClientIdentity{}, false
	}
	if resolve == nil {
		apiError(w, 403, "LAN ingress verification unavailable")
		return ip, api.ClientIdentity{}, false
	}
	client, err := resolve(netip.AddrPortFrom(ip, peer.Port()), local.AddrPort())
	if err != nil {
		apiError(w, 403, "cannot verify LAN ingress")
		return ip, client, false
	}
	return ip, client, true
}

func writeAPI(w http.ResponseWriter, value any) {
	writeAPIStatus(w, value, http.StatusOK)
}

func writeAPIStatus(w http.ResponseWriter, value any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, value, jsonv1.FormatDurationAsNano(true))
}

func apiSaveError(w http.ResponseWriter, err error) {
	log.WithError(err).Error("Could not apply and save API settings")
	apiError(w, 500, "could not apply and save settings; check the daemon log")
}

// The filesystem-protected Unix listener is the local administration boundary.
// Request headers cannot opt a TCP connection into this privilege.
func localAPISocket(r *http.Request) bool {
	local, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	return ok && local.Network() == "unix"
}
