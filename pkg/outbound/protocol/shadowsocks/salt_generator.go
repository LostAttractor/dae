package shadowsocks

import (
	"github.com/daeuniverse/dae/pkg/outbound/pkg/fastrand"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
)

type SaltGenerator interface{ Get() []byte }

// RandomSaltGenerator is the number of random bytes in each pooled salt.
type RandomSaltGenerator int

func (size RandomSaltGenerator) Get() []byte {
	salt := pool.GetBuffer(int(size))
	fastrand.Read(salt)
	return salt
}
