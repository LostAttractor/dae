/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package quicutils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"github.com/daeuniverse/dae/common"
)

var destConnId = []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}

func TestDeriveKeys(t *testing.T) {
	// https://datatracker.ietf.org/doc/html/rfc9001#name-keys
	keys, err := NewKeys(destConnId, Version_V1, common.NewGcm)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Close()

	t.Logf("%#v", keys)
	clientInitialSecret, _ := hex.DecodeString("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
	if !bytes.Equal(keys.clientInitialSecret, clientInitialSecret) {
		t.Fatal("key")
	}
	key, _ := hex.DecodeString("1f369613dd76d5467730efcbe3b1a22d")
	if !bytes.Equal(keys.key, key) {
		t.Fatal("key")
	}
	iv, _ := hex.DecodeString("fa044b2f42a3fd3b46fb255c")
	if !bytes.Equal(keys.iv, iv) {
		t.Fatal("iv")
	}
	hp, _ := hex.DecodeString("9f50449e04a0e810283a1e9933adedd2")
	if !bytes.Equal(keys.headerProtectionKey, hp) {
		t.Fatal("hp")
	}
}

func TestKeysHeaderProtection(t *testing.T) {
	for _, test := range []struct {
		name, connectionID, sample, packetNumber string
		version                                  Version
		flag, wantPacketNumber                   byte
	}{
		// RFC 9001 Appendix A.2 client Initial.
		{"v1", "8394c8f03e515708", "d1b1c98dd7689fb8ec11d242b123dc9b", "00000002", Version_V1, 0xc3, 0x7b},
		// Only the protected fields and sample from the draft Initial are needed.
		{"draft", "7f9863b69d513af6a050f0272dfe4dd1", "f09bb7d134541f214437ebaac82ad304", "2cce1ec1", Version_Draft, 0xcf, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			connectionID, err := hex.DecodeString(test.connectionID)
			if err != nil {
				t.Fatal(err)
			}
			sample, err := hex.DecodeString(test.sample)
			if err != nil {
				t.Fatal(err)
			}
			packetNumber, err := hex.DecodeString(test.packetNumber)
			if err != nil {
				t.Fatal(err)
			}
			keys, err := NewKeys(connectionID, test.version, common.NewGcm)
			if err != nil {
				t.Fatal(err)
			}
			defer keys.Close()
			flag := test.flag
			packetNumber, err = keys.HeaderProtection_(sample, true, &flag, packetNumber)
			if err != nil {
				t.Fatal(err)
			}
			if flag != 0xc0 || !bytes.Equal(packetNumber, []byte{test.wantPacketNumber}) {
				t.Fatalf("flag=%x packetNumber=%x, want c0 / %02x", flag, packetNumber, test.wantPacketNumber)
			}
		})
	}
}

func TestKeysPayloadDecrypt(t *testing.T) {
	// Fixed client keys for destConnId. The peer uses only the standard AES-GCM
	// implementation, independently of NewKeys and PayloadDecrypt.
	for _, test := range []struct {
		name    string
		version Version
		key, iv string
	}{
		{"draft", Version_Draft, "175257a31eb09dea9366d8bb79ad80ba", "6b26114b9cba2b63a9e8dd4f"},
		{"v1", Version_V1, "1f369613dd76d5467730efcbe3b1a22d", "fa044b2f42a3fd3b46fb255c"},
		{"v2", Version_V2, "8b1a0bc121284290a29e0971b5cd045d", "91f73e2351d8fa91660e909f"},
	} {
		t.Run(test.name, func(t *testing.T) {
			key, err := hex.DecodeString(test.key)
			if err != nil {
				t.Fatal(err)
			}
			nonce, err := hex.DecodeString(test.iv)
			if err != nil {
				t.Fatal(err)
			}
			block, err := aes.NewCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			peer, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatal(err)
			}
			packetNumber := []byte{1, 2}
			nonce[len(nonce)-2] ^= 1
			nonce[len(nonce)-1] ^= 2
			header := []byte("authenticated header")
			payload := []byte{Quic_FrameType_Crypto, 0, 3, 'a', 'b', 'c'}
			ciphertext := peer.Seal(nil, nonce, payload, header)

			keys, err := NewKeys(destConnId, test.version, common.NewGcm)
			if err != nil {
				t.Fatal(err)
			}
			defer keys.Close()
			plaintext, err := keys.PayloadDecrypt([]byte("prefix:"), ciphertext, packetNumber, header)
			if err != nil {
				t.Fatal(err)
			}
			want := append([]byte("prefix:"), payload...)
			if !bytes.Equal(plaintext, want) {
				t.Fatalf("plaintext = %x, want %x", plaintext, want)
			}
		})
	}
}

func TestKeysPayloadDecryptRejectsInvalidTag(t *testing.T) {
	keys, err := NewKeys(destConnId, Version_V1, common.NewGcm)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Close()
	if plaintext, err := keys.PayloadDecrypt(nil, make([]byte, 16), []byte{1}, []byte("header")); err == nil || plaintext != nil {
		t.Fatalf("PayloadDecrypt = %x, %v; want authentication error", plaintext, err)
	}
}
