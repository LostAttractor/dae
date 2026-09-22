// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const sessionCookieName = "dae_session"
const sessionLifetime = 7 * 24 * time.Hour

func (s *handler) sessionSignature(payload, host string) []byte {
	mac := hmac.New(sha256.New, []byte(s.options.APIKey))
	_, _ = mac.Write([]byte("dae-browser-session\x00" + host + "\x00" + payload))
	return mac.Sum(nil)
}

func (s *handler) validSession(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	payload, encoded, ok := strings.CutLast(cookie.Value, ".")
	if !ok {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || !hmac.Equal(signature, s.sessionSignature(payload, r.Host)) {
		return false
	}
	deadline, _, ok := strings.Cut(payload, ".")
	expires, err := strconv.ParseInt(deadline, 10, 64)
	return ok && err == nil && time.Now().Unix() < expires
}

func (s *handler) serveLogin(w http.ResponseWriter, r *http.Request) {
	if s.options.APIKey == "" {
		if _, ok := s.requireAdmin(w, r); !ok {
			return
		}
		// Keyless access clears stale cookies without creating a portable session.
		serveLogout(w, r)
		return
	}
	if !s.requireAPIKey(w, r) || !apiBody(w, r, nil) {
		return
	}
	cookie := newSessionCookie(r)
	cookie.Expires = time.Now().Add(sessionLifetime)
	cookie.MaxAge = int(sessionLifetime.Seconds())
	payload := strconv.FormatInt(cookie.Expires.Unix(), 10) + "." + rand.Text()
	cookie.Value = payload + "." + base64.RawURLEncoding.EncodeToString(s.sessionSignature(payload, r.Host))
	// The cookie contains a signed, expiring session, never the API key. Signing
	// with the configured key preserves reloads and invalidates sessions on rotation.
	http.SetCookie(w, cookie)
	w.WriteHeader(http.StatusNoContent)
}

func serveLogout(w http.ResponseWriter, r *http.Request) {
	if !apiBody(w, r, nil) {
		return
	}
	cookie := newSessionCookie(r)
	cookie.MaxAge = -1
	cookie.Expires = time.Unix(1, 0)
	http.SetCookie(w, cookie)
	w.WriteHeader(http.StatusNoContent)
}

func newSessionCookie(r *http.Request) *http.Cookie {
	return &http.Cookie{
		Name: sessionCookieName, Path: "/api", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil,
	}
}
