// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"

	"github.com/daeuniverse/dae/component/plugin"
	log "github.com/sirupsen/logrus"
)

// Downstream certificates identify only the intercepted ingress. Upstream TLS
// independently authenticates that ingress (or an explicitly rewritten target)
// when forwarding; selecting a local certificate has no network side effects.
func (h *Host) interceptionTLSConfig(flow plugin.Flow) *tls.Config {
	cfg := h.options.Authority.TLSConfig(flow.Host)
	cfg.SessionTicketsDisabled = true
	selectCertificate := cfg.GetCertificate
	cfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := selectCertificate(hello)
		if err != nil {
			return nil, err
		}
		connection, _ := plugin.IDs(hello.Context())
		fingerprint := sha256.Sum256(cert.Leaf.Raw)
		h.options.Logger.WithFields(log.Fields{
			"event": "mitm_certificate", "certificate_source": "single",
			"connection_id": connection, "host": flow.Host, "port": flow.Port,
			"certificate_id": fmt.Sprintf("%x", fingerprint[:8]),
			"dns_sans":       cert.Leaf.DNSNames, "ip_sans": cert.Leaf.IPAddresses,
		}).Trace("MITM client certificate selected")
		return cert, nil
	}
	return cfg
}
