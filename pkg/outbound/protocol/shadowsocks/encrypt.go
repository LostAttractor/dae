package shadowsocks

import (
	"crypto/cipher"
	"crypto/sha1"
	"io"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"golang.org/x/crypto/hkdf"
)

var (
	ShadowsocksReusedInfo = []byte("ss-subkey")
)

func GenerateSubKey(masterKey []byte, salt []byte) (subKey []byte, err error) {
	subKey = pool.GetBuffer(len(masterKey))
	kdf := hkdf.New(
		sha1.New,
		masterKey,
		salt,
		ShadowsocksReusedInfo,
	)
	_, err = io.ReadFull(kdf, subKey)
	return
}

func CreateCipher(masterKey []byte, salt []byte, cipherConf *ciphers.CipherConf) (cipher cipher.AEAD, err error) {
	subKey, err := GenerateSubKey(masterKey, salt)
	if err != nil {
		pool.PutBuffer(subKey)
		return nil, err
	}
	defer pool.PutBuffer(subKey)
	return cipherConf.NewCipher(subKey)
}
