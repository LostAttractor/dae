// SPDX-License-Identifier: AGPL-3.0-only

package mitmca

import (
	"crypto/tls"
	"fmt"
	"net"
)

// TLSConfig serves a single-host certificate bound to the supplied identity.
// It advertises HTTP/1.1; callers may enable additional supported protocols.
func (a *Authority) TLSConfig(host string) *tls.Config {
	host = normalizeHost(host)
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// SNI must agree with the intercepted ingress. Host syntax and CA
			// validity belong to the single certificate-issuance boundary.
			name := normalizeHost(hello.ServerName)
			if name != host && !(name == "" && net.ParseIP(host) != nil) {
				return nil, fmt.Errorf("mitm: TLS SNI differs from intercepted destination")
			}
			return a.ServerCertificate(host)
		},
	}
}
