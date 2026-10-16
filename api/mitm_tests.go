// SPDX-License-Identifier: AGPL-3.0-only

package api

import "time"

// MITMTest records a transparent MITM observation. The browser must also
// validate the challenge response over HTTPS; HTTPS acceptance uses /api/certificate.
type MITMTest struct {
	ID            string    `json:"id"`
	CAFingerprint string    `json:"ca_fingerprint"`
	StartedAt     time.Time `json:"started_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	MITMURL       string    `json:"mitm_url"`
	MITMEnabled   bool      `json:"mitm_enabled"`
	MITMObserved  bool      `json:"mitm_observed"`
}

type MITMTestProof struct {
	ID            string `json:"id"`
	CAFingerprint string `json:"ca_fingerprint"`
}
