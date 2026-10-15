package ciphers

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"time"
)

type CipherConf2022 struct {
	KeyLen         int
	SaltLen        int
	NonceLen       int
	TagLen         int
	NewCipher      func(key []byte) (cipher.AEAD, error)
	NewBlockCipher func(key []byte) (cipher.Block, error)
}

const (
	// Timestamp tolerance
	TimestampTolerance = 30 * time.Second

	// Salt storage duration
	SaltStorageDuration = 60 * time.Second
)

var (
	Aead2022CiphersConf = map[string]*CipherConf2022{
		"2022-blake3-aes-256-gcm": {KeyLen: 32, SaltLen: 32, NonceLen: 12, TagLen: 16, NewCipher: NewGcm, NewBlockCipher: aes.NewCipher},
		"2022-blake3-aes-128-gcm": {KeyLen: 16, SaltLen: 16, NonceLen: 12, TagLen: 16, NewCipher: NewGcm, NewBlockCipher: aes.NewCipher},
	}
)

// ValidateBase64PSK validates that the PSK is a valid base64 string with correct length
func ValidateBase64PSK(pskBase64 string, expectedKeyLen int) ([]byte, error) {
	if pskBase64 == "" {
		return nil, fmt.Errorf("PSK cannot be empty for SIP022 methods")
	}

	psk, err := base64.StdEncoding.DecodeString(pskBase64)
	if err != nil {
		return nil, fmt.Errorf("PSK must be valid base64 for SIP022 methods: %w", err)
	}

	if len(psk) != expectedKeyLen {
		return nil, fmt.Errorf("PSK length must be %d bytes for this method, got %d", expectedKeyLen, len(psk))
	}

	return psk, nil
}
