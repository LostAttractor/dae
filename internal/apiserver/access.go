// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"net/http"
	"net/netip"
)

// Policies compose a required privilege with an optional connection scope.
type accessPolicy uint8

const (
	accessPublic accessPolicy = 1 << iota
	accessAdmin
	accessLAN
	accessDevice
	accessLogin
)

type accessRole uint8

const (
	roleLAN accessRole = iota + 1
	roleAdmin
)

// Role controls privileges; self controls which device the route addresses.
// Administrator credentials never substitute for verified ingress identity.
type caller struct {
	role     accessRole
	self     bool
	mode     string
	ip       netip.Addr
	identity ClientIdentity
}

type endpoint func(http.ResponseWriter, *http.Request, caller)

// Every route declares its boundary at registration. No endpoint runs before
// authorization, including body parsing and resource/feature availability checks.
func (s *handler) route(mux *http.ServeMux, pattern string, policy accessPolicy, serve endpoint) {
	switch policy {
	case accessPublic, accessAdmin, accessLAN, accessDevice, accessLogin,
		accessAdmin | accessLAN, accessAdmin | accessDevice:
	default:
		panic("API route requires an explicit access policy")
	}
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if who, ok := s.authorize(w, r, policy); ok {
			serve(w, r, who)
		}
	})
}

func (s *handler) authorize(w http.ResponseWriter, r *http.Request, policy accessPolicy) (caller, bool) {
	who := caller{self: policy&(accessLAN|accessDevice) != 0}
	if policy == accessPublic {
		return who, true
	}
	// Creating a portable session requires the key even on the local socket.
	if policy == accessLogin && s.options.APIKey != "" {
		who.role, who.mode = roleAdmin, "api_key"
		return who, s.requireAPIKey(w, r)
	}
	if localAPISocket(r) {
		if who.self {
			apiError(w, http.StatusForbidden, "device self-service requires a direct LAN connection")
			return who, false
		}
		who.role, who.mode = roleAdmin, "unix"
		return who, true
	}
	needsAdmin := policy&(accessAdmin|accessLogin) != 0
	if s.options.APIKey != "" {
		// An explicit invalid credential must never fall back to a session or LAN.
		if r.Header.Get("Authorization") != "" {
			if !s.requireAPIKey(w, r) {
				return who, false
			}
			who.role, who.mode = roleAdmin, "api_key"
		} else if s.validSession(r) {
			who.role, who.mode = roleAdmin, "api_key"
		} else if needsAdmin {
			return who, s.requireAPIKey(w, r)
		}
	}
	if who.self || who.role != roleAdmin {
		var ok bool
		who.ip, who.identity, ok = apiClient(w, r, s.options.ResolveClient)
		if !ok {
			return who, false
		}
		if policy&accessDevice != 0 && (who.identity.LinkType != "ethernet" || who.identity.MAC == [6]byte{} || who.identity.MAC[0]&1 != 0) {
			apiError(w, http.StatusForbidden, "device self-service requires a verified Ethernet MAC; this connection has no device identity")
			return who, false
		}
		if who.role != roleAdmin {
			who.role, who.mode = roleLAN, "lan"
			if s.options.APIKey == "" {
				who.role = roleAdmin
			}
		}
	}
	return who, true
}
