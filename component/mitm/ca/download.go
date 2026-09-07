// SPDX-License-Identifier: AGPL-3.0-only

package mitmca

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/api"
)

// CertificatePEM exports only the public certificate.
func CertificatePEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// Fingerprint returns the colon-separated SHA-256 fingerprint of a certificate.
func Fingerprint(cert *x509.Certificate) string {
	digest := sha256.Sum256(cert.Raw)
	parts := make([]string, len(digest))
	for i, b := range digest {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// MobileConfig exports an unsigned Apple configuration profile containing just
// the public root certificate. iOS requires the user to install the profile
// and separately enable SSL trust for a manually downloaded root certificate.
func MobileConfig(cert *x509.Certificate) []byte {
	var name bytes.Buffer
	_ = xml.EscapeText(&name, []byte(cert.Subject.CommonName))
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadVersion</key><integer>1</integer>
<key>PayloadIdentifier</key><string>org.dae.mitm.%s</string>
<key>PayloadUUID</key><string>%s</string>
<key>PayloadDisplayName</key><string>%s</string>
<key>PayloadDescription</key><string>Install this root certificate to use dae HTTPS modules on this device. Enable full trust separately in Certificate Trust Settings.</string>
<key>PayloadRemovalDisallowed</key><false/>
<key>PayloadContent</key><array><dict>
<key>PayloadType</key><string>com.apple.security.root</string>
<key>PayloadVersion</key><integer>1</integer>
<key>PayloadIdentifier</key><string>org.dae.mitm.%s.certificate</string>
<key>PayloadUUID</key><string>%s</string>
<key>PayloadDisplayName</key><string>%s</string>
<key>PayloadCertificateFileName</key><string>dae-mitm-ca.cer</string>
<key>PayloadContent</key><data>%s</data>
</dict></array>
</dict></plist>
`, profileUUID(cert, "profile"), profileUUID(cert, "profile"), name.String(),
		profileUUID(cert, "profile"), profileUUID(cert, "certificate"), name.String(),
		base64.StdEncoding.EncodeToString(cert.Raw)))
}

func profileUUID(cert *x509.Certificate, label string) string {
	// UUIDv5 (DNS namespace): SHA-1 is used only to derive a stable identifier,
	// never for signatures or certificate verification.
	h := sha1.New()
	_, _ = h.Write([]byte{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8})
	_, _ = h.Write([]byte("org.dae.mitm." + label))
	_, _ = h.Write(cert.Raw)
	b := h.Sum(nil)[:16]
	b[6], b[8] = b[6]&0x0f|0x50, b[8]&0x3f|0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// Identity exposes only the public CA name and fingerprint.
func (a *Authority) Identity() api.Certificate {
	return api.Certificate{Name: a.certificate.Subject.CommonName, Fingerprint: a.Fingerprint()}
}

// Handler serves only the public certificate downloads.
func (a *Authority) Handler() http.Handler {
	cert := a.certificate
	type resource struct {
		contentType string
		filename    string
		body        []byte
	}
	resources := map[string]resource{
		"/ca.cer":          {"application/pkix-cert", "dae-mitm-ca.cer", bytes.Clone(cert.Raw)},
		"/ca.pem":          {"application/x-pem-file", "dae-mitm-ca.pem", CertificatePEM(cert)},
		"/ca.mobileconfig": {"application/x-apple-aspen-config", "dae-mitm-ca.mobileconfig", MobileConfig(cert)},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		resource, ok := resources[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", resource.contentType)
		w.Header().Set("Content-Length", strconv.Itoa(len(resource.body)))
		if resource.filename != "" {
			w.Header().Set("Content-Disposition", `attachment; filename="`+resource.filename+`"`)
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write(resource.body)
		}
	})
}
