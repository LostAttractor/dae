// SPDX-License-Identifier: AGPL-3.0-only

package api

import "time"

// CertificateTest records endpoint observations, not a device-wide trust verdict.
// The browser must also validate the challenge response over verified HTTPS.
type CertificateTest struct {
	ID            string    `json:"id"`
	CAFingerprint string    `json:"ca_fingerprint"`
	StartedAt     time.Time `json:"started_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	TrustURL      string    `json:"trust_url"`
	MITMURL       string    `json:"mitm_url"`
	MITMEnabled   bool      `json:"mitm_enabled"`
	TrustObserved bool      `json:"trust_observed"`
	MITMObserved  bool      `json:"mitm_observed"`
}

type CertificateTestProof struct {
	ID            string `json:"id"`
	Stage         string `json:"stage"`
	CAFingerprint string `json:"ca_fingerprint"`
}
