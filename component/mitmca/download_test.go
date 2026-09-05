// SPDX-License-Identifier: AGPL-3.0-only

package mitmca

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCertificateDownloadsContainOnlyPublicCertificate(t *testing.T) {
	a, _, _ := testAuthority(t)
	handler := a.Handler()
	for _, test := range []struct {
		path string
		mime string
		body []byte
	}{
		{"/ca.cer", "application/pkix-cert", a.certificate.Raw},
		{"/ca.pem", "application/x-pem-file", CertificatePEM(a.certificate)},
		{"/ca.mobileconfig", "application/x-apple-aspen-config", MobileConfig(a.certificate)},
	} {
		t.Run(test.path, func(t *testing.T) {
			result := httptest.NewRecorder()
			handler.ServeHTTP(result, httptest.NewRequest(http.MethodGet, test.path, nil))
			if result.Code != http.StatusOK || result.Header().Get("Content-Type") != test.mime || !bytes.Equal(result.Body.Bytes(), test.body) {
				t.Fatalf("bad response: code=%d mime=%s", result.Code, result.Header().Get("Content-Type"))
			}
			if bytes.Contains(result.Body.Bytes(), []byte("PRIVATE KEY")) {
				t.Fatal("download included private key")
			}
			head := httptest.NewRecorder()
			handler.ServeHTTP(head, httptest.NewRequest(http.MethodHead, test.path, nil))
			if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("Content-Length") != result.Header().Get("Content-Length") {
				t.Fatal("invalid HEAD response")
			}
		})
	}
	for _, path := range []string{"/ca.key", "/../ca.key", "/other", "/ca.pem/extra"} {
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, httptest.NewRequest(http.MethodGet, path, nil))
		if result.Code != http.StatusNotFound {
			t.Errorf("unknown/private path %s returned %d", path, result.Code)
		}
	}
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, httptest.NewRequest(http.MethodPost, "/ca.cer", nil))
	if result.Code != http.StatusMethodNotAllowed || result.Header().Get("Allow") != "GET, HEAD" {
		t.Fatal("accepted certificate mutation request")
	}
}

func TestMobileConfigEscapesNameAndContainsRoot(t *testing.T) {
	a, _, _ := testAuthority(t)
	a.certificate.Subject.CommonName = `<ca> & "quoted"`
	profile := MobileConfig(a.certificate)
	decoder := xml.NewDecoder(bytes.NewReader(profile))
	var certs [][]byte
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("malformed profile XML: %v", err)
		}
		if start, ok := token.(xml.StartElement); ok && start.Name.Local == "data" {
			var value string
			if err := decoder.DecodeElement(&value, &start); err != nil {
				t.Fatal(err)
			}
			data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
			if err != nil {
				t.Fatal(err)
			}
			certs = append(certs, data)
		}
	}
	if len(certs) != 1 || !bytes.Equal(certs[0], a.certificate.Raw) {
		t.Fatal("profile does not contain exactly the public root")
	}
	if !bytes.Equal(profile, MobileConfig(a.certificate)) || profileUUID(a.certificate, "profile") == profileUUID(a.certificate, "certificate") {
		t.Fatal("profile UUIDs are unstable or duplicated")
	}
}
