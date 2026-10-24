// SPDX-License-Identifier: AGPL-3.0-only
package apiserver

import (
	"net/http"
	"net/netip"
	"strings"

	"github.com/daeuniverse/dae/api"
)

type accessPolicy uint8

const (
	accessPublic accessPolicy = 1 << iota
	accessUser
	accessAdmin
	accessLAN
	accessDevice
	accessLogin
	accessDirect
	accessBootstrap
)

type accessRole uint8

const (
	roleUser accessRole = iota + 1
	roleAdmin
)

type caller struct {
	role     accessRole
	self     bool
	mode     string
	ip       netip.Addr
	identity api.ClientIdentity
}
type endpoint func(http.ResponseWriter, *http.Request, caller)

func (s *Handler) route(mux *http.ServeMux, pattern string, policy accessPolicy, serve endpoint) {
	switch policy {
	case accessPublic, accessUser, accessAdmin, accessLAN, accessDevice, accessLogin, accessAdmin | accessLAN, accessAdmin | accessDevice, accessUser | accessDirect, accessPublic | accessDirect | accessBootstrap, accessUser | accessDirect | accessBootstrap, accessUser | accessBootstrap:
	default:
		panic("API route requires an explicit access policy")
	}
	if s.policies == nil {
		s.policies = make(map[string]accessPolicy)
	}
	s.policies[pattern] = policy
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if who, ok := s.authorize(w, r, policy); ok {
			serve(w, r, who)
		}
	})
}

func (s *Handler) authorize(w http.ResponseWriter, r *http.Request, policy accessPolicy) (caller, bool) {
	who := caller{self: policy&(accessLAN|accessDevice) != 0}
	proxied := proxyRequest(r)
	if proxied && policy&(accessLAN|accessDevice|accessDirect) != 0 {
		apiError(w, 403, "this operation requires a direct connection, not an API reverse proxy")
		return who, false
	}
	if localAPISocket(r) && policy != accessLogin {
		who.role, who.mode = roleAdmin, "unix"
		if who.self {
			apiError(w, 403, "current-device operations require a LAN identity; use the explicit device API on Unix")
			return who, false
		}
		return who, true
	}
	// Only CA installation and challenge creation may use an insecure transport or Web origin.
	cookies := r.CookiesNamed(sessionCookieName)
	if r.TLS == nil || strings.HasPrefix(strings.ToLower(r.Header.Get("Origin")), "http://") {
		if policy&accessBootstrap == 0 || len(r.Header.Values("Authorization")) != 0 || len(cookies) != 0 {
			apiError(w, 403, "management requires HTTPS; HTTP is only for anonymous CA setup")
			return who, false
		}
	}
	if policy&accessPublic != 0 {
		return who, true
	}
	if len(r.Header.Values("Authorization")) != 0 || policy == accessLogin {
		var ok bool
		who.role, ok = s.keyRole(r)
		if !ok {
			return who, authenticationError(w)
		}
	} else if len(cookies) != 0 {
		var ok bool
		if len(cookies) == 1 {
			who.role, ok = s.sessionRole(cookies[0].Value, r.Host)
		}
		if !ok {
			w.Header().Set("X-Dae-Session-Invalid", "1")
			w.Header().Add("Access-Control-Expose-Headers", "X-Dae-Session-Invalid")
			return who, authenticationError(w)
		}
	} else if policy&accessAdmin != 0 || !s.options.AllowLANAnonymous || proxied {
		return who, authenticationError(w)
	}
	if who.role != 0 {
		who.mode = "user_key"
		if who.role == roleAdmin {
			who.mode = "admin_key"
		}
	}
	if policy&accessAdmin != 0 && who.role != roleAdmin {
		apiError(w, 403, "administrator access required")
		return who, false
	}
	if who.self || who.role == 0 {
		var ok bool
		who.ip, who.identity, ok = apiClient(w, r, s.options.ResolveClient)
		if !ok {
			return who, false
		}
		if policy&accessDevice != 0 && (who.identity.LinkType != "ethernet" || who.identity.MAC == [6]byte{} || who.identity.MAC[0]&1 != 0) {
			apiError(w, 403, "current-device operations require a verified Ethernet MAC")
			return who, false
		}
		if who.role == 0 {
			who.role, who.mode = roleUser, "lan"
		}
	}
	return who, true
}
