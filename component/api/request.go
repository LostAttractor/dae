// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	json "encoding/json/v2"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

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
		host = netip.AddrPortFrom(ip, 80)
	}
	local, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		return false
	}
	address, err := netip.ParseAddrPort(local.String())
	return err == nil && address.Port() == host.Port() &&
		address.Addr().Unmap().WithZone("") == host.Addr().Unmap().WithZone("")
}

func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	origins := r.Header.Values("Origin")
	if len(origins) == 0 {
		return true // Non-browser clients can use the API without Origin.
	}
	if len(origins) != 1 {
		return false
	}
	origin, err := url.Parse(origins[0])
	if err != nil {
		return false
	}
	expected := url.URL{Host: r.Host}
	port, expectedPort := origin.Port(), expected.Port()
	if port == "" {
		port = "80"
	}
	if expectedPort == "" {
		expectedPort = "80"
	}
	return origin.Scheme == "http" && strings.EqualFold(origin.Hostname(), expected.Hostname()) && port == expectedPort &&
		origin.User == nil && origin.Path == "" && origin.RawQuery == "" && origin.Fragment == ""
}

func apiError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, map[string]string{"error": message})
}

// A nil destination requires an empty body (membership changes and deletes).
func apiBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
	if err != nil {
		apiError(w, 413, "request body exceeds 1 KiB or cannot be read")
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

func apiDevice(w http.ResponseWriter, r *http.Request, resolve func(netip.Addr) ([6]byte, error)) (netip.Addr, [6]byte, bool) {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		apiError(w, 400, "cannot read the connection source address")
		return netip.Addr{}, [6]byte{}, false
	}
	ip := peer.Addr().Unmap()
	mac, err := resolve(ip)
	if err != nil {
		apiError(w, 403, "cannot identify this device: "+err.Error())
		return ip, mac, false
	}
	return ip, mac, true
}

func writeAPI(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.MarshalWrite(w, value)
}

func apiSaveError(w http.ResponseWriter, err error) {
	log.WithError(err).Error("Could not apply and save API settings")
	apiError(w, 500, "could not apply and save settings; check the daemon log")
}
