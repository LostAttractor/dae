// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"net/http"
	"net/netip"
)

type accessPolicy uint8

const (
	accessPublic accessPolicy = iota + 1
	accessAdmin
	accessLAN
	accessDevice
	accessLogin
)

// caller contains only evidence verified for this request. Administrator
// credentials never substitute for the ingress identity of a self-service route.
type caller struct {
	policy   accessPolicy
	mode     string
	ip       netip.Addr
	identity ClientIdentity
}

type endpoint func(http.ResponseWriter, *http.Request, caller)

// Every route declares its boundary at registration. No endpoint runs before
// authorization, including body parsing and resource/feature availability checks.
func (s *handler) route(mux *http.ServeMux, pattern string, policy accessPolicy, serve endpoint) {
	if policy < accessPublic || policy > accessLogin {
		panic("API route requires an explicit access policy")
	}
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if who, ok := s.authorize(w, r, policy); ok {
			serve(w, r, who)
		}
	})
}

func (s *handler) authorize(w http.ResponseWriter, r *http.Request, policy accessPolicy) (caller, bool) {
	who := caller{policy: policy}
	switch policy {
	case accessPublic:
		return who, true
	case accessLogin:
		// Creating a session always requires the key when one is configured;
		// neither an existing session nor the Unix socket can mint another one.
		if s.options.APIKey != "" {
			who.mode = "api_key"
			return who, s.requireAPIKey(w, r)
		}
		fallthrough
	case accessAdmin:
		if localAPISocket(r) {
			who.mode = "unix"
			return who, true
		}
		if s.options.APIKey != "" {
			who.mode = "api_key"
			// Explicit credentials take precedence over a saved session.
			if r.Header.Get("Authorization") == "" && s.validSession(r) {
				return who, true
			}
			return who, s.requireAPIKey(w, r)
		}
		fallthrough
	case accessLAN, accessDevice:
		if localAPISocket(r) {
			apiError(w, http.StatusForbidden, "device self-service requires a direct LAN connection")
			return who, false
		}
		who.mode = "lan"
		var ok bool
		who.ip, who.identity, ok = apiClient(w, r, s.options.ResolveClient)
		if !ok {
			return who, false
		}
		if policy == accessDevice && (who.identity.LinkType != "ethernet" || who.identity.MAC == [6]byte{} || who.identity.MAC[0]&1 != 0) {
			apiError(w, http.StatusForbidden, "device self-service requires a verified Ethernet MAC; this connection has no device identity")
			return who, false
		}
		return who, true
	default:
		panic("unknown API access policy")
	}
}
