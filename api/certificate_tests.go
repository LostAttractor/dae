// SPDX-License-Identifier: AGPL-3.0-only

package api

import "time"

// CertificateTest is proved once by HTTPS using a temporary leaf issued for this
// source/router IP pair at or after Start. Management leaves cannot prove it.
// Reading this record from POST alone is not evidence of browser trust.
type CertificateTest struct {
	ID            string    `json:"id"`
	CAFingerprint string    `json:"ca_fingerprint"`
	ExpiresAt     time.Time `json:"expires_at"`
}
