// SPDX-License-Identifier: AGPL-3.0-only
package apiserver

import (
	"net/http"
	"strings"

	"github.com/daeuniverse/dae/api"
)

func validOrigin(r *http.Request) bool {
	values := r.Header.Values("Origin")
	if len(values) != 1 {
		return false
	}
	_, err := api.NormalizeOrigin(values[0])
	return err == nil
}

// Challenge proofs use their own origin binding and never carry credentials.
func allowOrigin(w http.ResponseWriter, r *http.Request) {
	if validOrigin(r) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Add("Vary", "Origin")
	}
}

func (s *Handler) originAllowed(r *http.Request) bool {
	if !validOrigin(r) {
		return false
	}
	if sameOrigin(r) {
		return true
	}
	return s.webOriginAllowed(r.Header.Get("Origin"))
}

func (s *Handler) webOriginAllowed(raw string) bool {
	origin, err := api.NormalizeOrigin(raw)
	if err != nil {
		return false
	}
	for _, value := range s.options.WebOrigins {
		allowed, err := api.NormalizeOrigin(value)
		if err == nil && origin == allowed {
			return true
		}
	}
	return false
}

// Forwarding headers only remove direct-connection capabilities; none supply identity.
func proxyRequest(r *http.Request) bool {
	for name := range r.Header {
		name = strings.ToLower(name)
		if name == "x-dae-proxy" || name == "forwarded" || name == "x-real-ip" || strings.HasPrefix(name, "x-forwarded-") {
			return true
		}
	}
	return false
}

func (s *Handler) prepareRequest(w http.ResponseWriter, r *http.Request) bool {
	if !localAPISocket(r) && !localIPHost(r) {
		apiError(w, 403, "use the API listener IP address and port")
		return false
	}
	if proxyRequest(r) && (localAPISocket(r) || r.TLS == nil) {
		apiError(w, 403, "API reverse proxies require an HTTPS TCP upstream")
		return false
	}
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && strings.HasPrefix(r.URL.Path, "/api/certificate/tests/") {
		if len(r.Header.Values("Origin")) != 0 {
			if !validOrigin(r) {
				apiError(w, 403, "this Web origin is not allowed")
				return false
			}
			allowOrigin(w, r)
		}
		return true
	}
	if len(r.Header.Values("Origin")) != 0 {
		if !s.originAllowed(r) {
			apiError(w, 403, "this Web origin is not allowed")
			return false
		}
		allowOrigin(w, r)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	// Preflight grants no access; reject cross-site on the actual request so its error remains readable.
	if r.Method == http.MethodOptions {
		return true
	}
	site := r.Header.Get("Sec-Fetch-Site")
	// Safari installs the profile via navigation, whose GET has no Origin header.
	if site == "same-site" && len(r.Header.Values("Origin")) == 0 && r.TLS != nil &&
		r.Method == http.MethodGet && r.URL.Path == "/api/certificate/ca.mobileconfig" &&
		r.Header.Get("Sec-Fetch-Mode") == "navigate" && r.Header.Get("Sec-Fetch-Dest") == "document" {
		if referrers := r.Header.Values("Referer"); len(referrers) == 1 &&
			strings.HasPrefix(referrers[0], "https://") &&
			s.webOriginAllowed(strings.TrimSuffix(referrers[0], "/")) {
			return true
		}
	}
	if site == "cross-site" || (len(r.Header.Values("Origin")) == 0 && site != "" && site != "same-origin" && site != "none") {
		apiError(w, 403, "Web API access must be same-site with an approved origin or reverse-proxied")
		return false
	}
	if len(r.Header.Values("Authorization")) == 0 && len(r.CookiesNamed(sessionCookieName)) != 0 && len(r.Header.Values("Origin")) == 0 && r.Header.Get("Sec-Fetch-Site") != "same-origin" {
		apiError(w, 403, "browser sessions require a verified Web origin")
		return false
	}
	mutation := r.Method == http.MethodPut || r.Method == http.MethodDelete || r.Method == http.MethodPost
	if mutation && (strings.HasPrefix(r.URL.Path, "/api/") || len(r.CookiesNamed(sessionCookieName)) != 0) && r.Header.Get("X-Dae-API") != "1" {
		apiError(w, 403, "changes require X-Dae-API: 1")
		return false
	}
	return true
}

func (s *Handler) preflight(w http.ResponseWriter, r *http.Request) {
	if !s.originAllowed(r) {
		apiError(w, 403, "this Web origin is not allowed")
		return
	}
	for header := range strings.SplitSeq(strings.ToLower(r.Header.Get("Access-Control-Request-Headers")), ",") {
		switch strings.TrimSpace(header) {
		case "authorization":
			if r.TLS == nil {
				apiError(w, 403, "API credentials require HTTPS")
				return
			}
		case "", "content-type", "x-dae-api", "x-dae-mitm":
		default:
			apiError(w, 403, "unsupported request header")
			return
		}
	}
	switch r.Header.Get("Access-Control-Request-Method") {
	case "GET", "HEAD", "POST", "PUT", "DELETE":
	default:
		apiError(w, 403, "unsupported request method")
		return
	}
	// Preflight never authenticates; the actual request independently checks its key, cookie or LAN identity.
	w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, POST, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Dae-API, X-Dae-MITM")
	w.Header().Add("Vary", "Access-Control-Request-Headers")
	w.Header().Add("Vary", "Access-Control-Request-Method")
	w.WriteHeader(http.StatusNoContent)
}
