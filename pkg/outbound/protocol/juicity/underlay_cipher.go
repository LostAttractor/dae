package juicity

import (
	"crypto/sha1"
	"fmt"
	"io"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks"
	"golang.org/x/crypto/hkdf"
)

// EncryptUDPFromPool returns shadowBytes from pool.
// the shadowBytes MUST be put back.
func EncryptUDPFromPool(key *shadowsocks.Key, b []byte, salt []byte, reusedInfo []byte) (shadowBytes []byte, err error) {
	var buf = pool.GetBuffer(key.CipherConf.SaltLen + len(b) + key.CipherConf.TagLen)
	defer func() {
		if err != nil {
			pool.PutBuffer(buf)
		}
	}()
	copy(buf, salt)
	subKey := pool.GetBuffer(key.CipherConf.KeyLen)
	defer pool.PutBuffer(subKey)
	kdf := hkdf.New(
		sha1.New,
		key.MasterKey,
		buf[:key.CipherConf.SaltLen],
		reusedInfo,
	)
	_, err = io.ReadFull(kdf, subKey)
	if err != nil {
		return nil, err
	}
	ciph, err := key.CipherConf.NewCipher(subKey)
	if err != nil {
		return nil, err
	}
	_ = ciph.Seal(buf[key.CipherConf.SaltLen:key.CipherConf.SaltLen], ciphers.ZeroNonce[:key.CipherConf.NonceLen], b, nil)
	return buf, nil
}

// DecryptUDP will decrypt the data in place
func DecryptUDP(writeTo []byte, key *shadowsocks.Key, shadowBytes []byte, reusedInfo []byte) (n int, err error) {
	if len(shadowBytes) < key.CipherConf.SaltLen {
		return 0, fmt.Errorf("short length to decrypt")
	}
	subKey := pool.GetBuffer(key.CipherConf.KeyLen)
	defer pool.PutBuffer(subKey)
	kdf := hkdf.New(
		sha1.New,
		key.MasterKey,
		shadowBytes[:key.CipherConf.SaltLen],
		reusedInfo,
	)
	_, err = io.ReadFull(kdf, subKey)
	if err != nil {
		return
	}
	ciph, err := key.CipherConf.NewCipher(subKey)
	if err != nil {
		return
	}
	writeTo, err = ciph.Open(writeTo[:0], ciphers.ZeroNonce[:key.CipherConf.NonceLen], shadowBytes[key.CipherConf.SaltLen:], nil)
	if err != nil {
		return 0, err
	}
	return len(writeTo), nil
}
