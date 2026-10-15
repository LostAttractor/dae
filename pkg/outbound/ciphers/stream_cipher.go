package ciphers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"errors"

	"github.com/daeuniverse/dae/pkg/outbound/common"
	rand "github.com/daeuniverse/dae/pkg/outbound/pkg/fastrand"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/dgryski/go-camellia"
	"github.com/dgryski/go-idea"
	"github.com/dgryski/go-rc2"
	"gitlab.com/yawning/chacha20.git"
	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/salsa20/salsa"
)

var errEmptyPassword = errors.New("empty key")

type DecOrEnc int

const (
	Decrypt DecOrEnc = iota
	Encrypt
)

func newAESCTRStream(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

func newAESOFBStream(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewOFB(block, iv), nil
}

func newCFBStream(block cipher.Block, err error, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	if err != nil {
		return nil, err
	}
	if doe == Encrypt {
		return cipher.NewCFBEncrypter(block, iv), nil
	} else {
		return cipher.NewCFBDecrypter(block, iv), nil
	}
}

func newAESCFBStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	return newCFBStream(block, err, iv, doe)
}

func newDESStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := des.NewCipher(key)
	return newCFBStream(block, err, iv, doe)
}

func newBlowFishStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := blowfish.NewCipher(key)
	return newCFBStream(block, err, iv, doe)
}

func newCast5Stream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := cast5.NewCipher(key)
	return newCFBStream(block, err, iv, doe)
}

func newRC4MD5Stream(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
	h := md5.New()
	h.Write(key)
	h.Write(iv)
	rc4key := h.Sum(nil)

	return rc4.NewCipher(rc4key)
}

func newChaCha20Stream(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
	return chacha20.New(key, iv)
}

type salsaStreamCipher struct {
	nonce   [8]byte
	key     [32]byte
	counter int
}

func (c *salsaStreamCipher) XORKeyStream(dst, src []byte) {
	var buf []byte
	padLen := c.counter % 64
	dataSize := len(src) + padLen
	if cap(dst) >= dataSize {
		buf = dst[:dataSize]
	} else {
		buf = pool.GetBuffer(dataSize)
		defer pool.PutBuffer(buf)
	}

	var subNonce [16]byte
	copy(subNonce[:], c.nonce[:])
	binary.LittleEndian.PutUint64(subNonce[len(c.nonce):], uint64(c.counter/64))

	// It's difficult to avoid data copy here. src or dst maybe slice from
	// Conn.Read/Write, which can't have padding.
	copy(buf[padLen:], src[:])
	salsa.XORKeyStream(buf, buf, &subNonce, &c.key)
	copy(dst, buf[padLen:])

	c.counter += len(src)
}

func newSalsa20Stream(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
	var c salsaStreamCipher
	copy(c.nonce[:], iv[:8])
	copy(c.key[:], key[:32])
	return &c, nil
}

func newCamelliaStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := camellia.New(key)
	return newCFBStream(block, err, iv, doe)
}

func newIdeaStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := idea.NewCipher(key)
	return newCFBStream(block, err, iv, doe)
}

func newRC2Stream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := rc2.New(key, 16)
	return newCFBStream(block, err, iv, doe)
}

func newRC4Stream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	return rc4.NewCipher(key)
}

type noneStream struct{}

func (*noneStream) XORKeyStream(dst, src []byte) {
	copy(dst, src)
}

func newNoneStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	return new(noneStream), nil
}

type cipherInfo struct {
	keyLen    int
	ivLen     int
	newStream func(key, iv []byte, doe DecOrEnc) (cipher.Stream, error)
}

var streamCipherMethod = map[string]*cipherInfo{
	"aes-128-cfb":      {16, 16, newAESCFBStream},
	"aes-192-cfb":      {24, 16, newAESCFBStream},
	"aes-256-cfb":      {32, 16, newAESCFBStream},
	"aes-128-ctr":      {16, 16, newAESCTRStream},
	"aes-192-ctr":      {24, 16, newAESCTRStream},
	"aes-256-ctr":      {32, 16, newAESCTRStream},
	"aes-128-ofb":      {16, 16, newAESOFBStream},
	"aes-192-ofb":      {24, 16, newAESOFBStream},
	"aes-256-ofb":      {32, 16, newAESOFBStream},
	"des-cfb":          {8, 8, newDESStream},
	"bf-cfb":           {16, 8, newBlowFishStream},
	"cast5-cfb":        {16, 8, newCast5Stream},
	"rc4-md5":          {16, 16, newRC4MD5Stream},
	"rc4-md5-6":        {16, 6, newRC4MD5Stream},
	"chacha20":         {32, 8, newChaCha20Stream},
	"chacha20-ietf":    {32, 12, newChaCha20Stream},
	"salsa20":          {32, 8, newSalsa20Stream},
	"camellia-128-cfb": {16, 16, newCamelliaStream},
	"camellia-192-cfb": {24, 16, newCamelliaStream},
	"camellia-256-cfb": {32, 16, newCamelliaStream},
	"idea-cfb":         {16, 8, newIdeaStream},
	"rc2-cfb":          {16, 8, newRC2Stream},
	"rc4":              {16, 0, newRC4Stream},
	"none":             {16, 0, newNoneStream},
	"plain":            {16, 0, newNoneStream},
}

type StreamCipher struct {
	enc  cipher.Stream
	dec  cipher.Stream
	key  []byte
	info *cipherInfo
	iv   []byte
}

// NewStreamCipher creates a cipher that can be used in Dial() etc.
// Use cipher.Clone() to create a new cipher with the same method and password
// to avoid the cost of repeated cipher initialization.
func NewStreamCipher(method, password string) (c *StreamCipher, err error) {
	if password == "" {
		return nil, errEmptyPassword
	}
	mi, ok := streamCipherMethod[method]
	if !ok {
		return nil, errors.New("Unsupported encryption method: " + method)
	}

	key := common.EVPBytesToKey(password, mi.keyLen)

	c = &StreamCipher{key: key, info: mi}

	return c, nil
}

func (c *StreamCipher) EncryptInited() bool {
	return c.enc != nil
}

func (c *StreamCipher) DecryptInited() bool {
	return c.dec != nil
}

// InitEncrypt initializes the block cipher with CFB mode, returns IV.
func (c *StreamCipher) InitEncrypt() (iv []byte, err error) {
	if c.EncryptInited() {
		return c.iv, nil
	}
	if c.iv == nil {
		iv = make([]byte, c.info.ivLen)
		rand.Read(iv)
		c.iv = iv
	} else {
		iv = c.iv
	}
	if c.enc, err = c.info.newStream(c.key, iv, Encrypt); err != nil {
		return nil, err
	}
	return iv, nil
}

func (c *StreamCipher) NewEncryptor(iv []byte) (enc cipher.Stream, err error) {
	iv = iv[:c.info.ivLen]
	rand.Read(iv)
	return c.info.newStream(c.key, iv, Encrypt)
}

func (c *StreamCipher) InitDecrypt(iv []byte) (err error) {
	c.dec, err = c.info.newStream(c.key, iv, Decrypt)
	return err
}

func (c *StreamCipher) NewDecryptor(iv []byte) (dec cipher.Stream, err error) {
	return c.info.newStream(c.key, iv, Decrypt)
}

func (c *StreamCipher) Encrypt(dst, src []byte) {
	c.enc.XORKeyStream(dst, src)
}

func (c *StreamCipher) Decrypt(dst, src []byte) {
	c.dec.XORKeyStream(dst, src)
}

// Clone creates an independent connection cipher with a fresh IV.
func (c *StreamCipher) Clone() *StreamCipher {
	return &StreamCipher{key: c.key, info: c.info}
}

func (c *StreamCipher) Key() []byte {
	return c.key
}

func (c *StreamCipher) InfoIVLen() int {
	return c.info.ivLen
}
