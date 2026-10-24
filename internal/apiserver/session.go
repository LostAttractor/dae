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

	"github.com/daeuniverse/dae/api"
)

const (
	sessionLifetime   = 7 * 24 * time.Hour
	sessionCookieName = "__Host-dae-session"
)

func sessionCookie(value string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name: sessionCookieName, Value: value, Path: "/", Expires: expires,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	}
}

func (s *Handler) sessionKey(role accessRole) string {
	if role == roleAdmin {
		return s.options.AdminKey
	}
	if role == roleUser {
		return s.options.UserKey
	}
	return ""
}
func sessionSignature(payload, host, key string) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte("dae-session\x00" + host + "\x00" + payload))
	return mac.Sum(nil)
}
func (s *Handler) sessionRole(token, host string) (accessRole, bool) {
	payload, signature, ok := strings.CutLast(token, ".")
	if !ok {
		return 0, false
	}
	parts := strings.Split(payload, ".")
	if len(parts) != 4 || parts[0] != "dae1" {
		return 0, false
	}
	role := roleUser
	if parts[1] == "admin" {
		role = roleAdmin
	} else if parts[1] != "user" {
		return 0, false
	}
	key := s.sessionKey(role)
	expires, err := strconv.ParseInt(parts[2], 10, 64)
	if key == "" || err != nil || time.Now().Unix() >= expires {
		return 0, false
	}
	signatureBytes, err := base64.RawURLEncoding.DecodeString(signature)
	return role, err == nil && hmac.Equal(signatureBytes, sessionSignature(payload, host, key))
}
func (s *Handler) serveLogin(w http.ResponseWriter, r *http.Request, who caller) {
	if !apiBody(w, r, nil) {
		return
	}
	result := api.Session{Role: "user"}
	if who.role == roleAdmin {
		result.Role = "admin"
	}
	result.ExpiresAt = time.Now().Add(sessionLifetime).Truncate(time.Second)
	payload := "dae1." + result.Role + "." + strconv.FormatInt(result.ExpiresAt.Unix(), 10) + "." + rand.Text()
	token := payload + "." + base64.RawURLEncoding.EncodeToString(sessionSignature(payload, r.Host, s.sessionKey(who.role)))
	http.SetCookie(w, sessionCookie(token, result.ExpiresAt))
	writeAPI(w, result)
}
func serveLogout(w http.ResponseWriter, r *http.Request, _ caller) {
	if apiBody(w, r, nil) {
		cookie := sessionCookie("", time.Unix(1, 0))
		cookie.MaxAge = -1
		http.SetCookie(w, cookie)
		w.WriteHeader(http.StatusNoContent)
	}
}
