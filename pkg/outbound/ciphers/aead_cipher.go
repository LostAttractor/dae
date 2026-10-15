package ciphers

import (
	"crypto/aes"
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
)

type CipherConf struct {
	KeyLen    int
	SaltLen   int
	NonceLen  int
	TagLen    int
	NewCipher func(key []byte) (cipher.AEAD, error)
}

const (
	MaxNonceSize = 12
)

var (
	AeadCiphersConf = map[string]*CipherConf{
		"chacha20-ietf-poly1305": {KeyLen: 32, SaltLen: 32, NonceLen: 12, TagLen: 16, NewCipher: chacha20poly1305.New},
		"chacha20-poly1305":      {KeyLen: 32, SaltLen: 32, NonceLen: 12, TagLen: 16, NewCipher: chacha20poly1305.New},
		"aes-256-gcm":            {KeyLen: 32, SaltLen: 32, NonceLen: 12, TagLen: 16, NewCipher: NewGcm},
		"aes-128-gcm":            {KeyLen: 16, SaltLen: 16, NonceLen: 12, TagLen: 16, NewCipher: NewGcm},
	}
	ZeroNonce         [MaxNonceSize]byte
	JuicityReusedInfo = []byte("juicity-reused-info")
)

func NewGcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
