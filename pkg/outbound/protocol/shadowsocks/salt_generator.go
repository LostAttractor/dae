package shadowsocks

import (
	"crypto/rand"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
)

type SaltGenerator interface{ Get() []byte }

// RandomSaltGenerator is the number of random bytes in each pooled salt.
type RandomSaltGenerator int

func (size RandomSaltGenerator) Get() []byte {
	salt := pool.GetBuffer(int(size))
	rand.Read(salt)
	return salt
}
