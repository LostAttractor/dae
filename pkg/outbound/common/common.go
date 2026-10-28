/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"crypto/sha256"
	"net/url"

	"github.com/google/uuid"
)

var IntSize = 32 << (^uint(0) >> 63)

func SetValue(values *url.Values, key string, value string) {
	if value == "" {
		return
	}
	values.Set(key, value)
}

func BoolToString(b bool) string {
	if b {
		return "1"
	} else {
		return "0"
	}
}

func GenerateCertChainHash(rawCerts [][]byte) (chainHash []byte) {
	for _, cert := range rawCerts {
		certHash := sha256.Sum256(cert)
		if chainHash == nil {
			chainHash = certHash[:]
		} else {
			newHash := sha256.Sum256(append(chainHash, certHash[:]...))
			chainHash = newHash[:]
		}
	}
	return chainHash
}

func BytesIncBigEndian(b []byte) {
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			break
		}
	}
}

func BytesIncLittleEndian(b []byte) {
	for i := 0; i < len(b); i++ {
		b[i]++
		if b[i] != 0 {
			break
		}
	}
}

// StringToUUID5 derives a UUID v5 in the nil namespace.
func StringToUUID5(str string) string {
	return uuid.NewSHA1(uuid.Nil, []byte(str)).String()
}
