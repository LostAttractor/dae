package proto

import (
	"github.com/daeuniverse/dae/pkg/outbound/common"
)

func NewAuthAES128SHA1() IProtocol {
	a := &authAES128{
		salt:       "auth_aes128_sha1",
		hmac:       common.HmacSHA1,
		hashDigest: common.SHA1Sum,
		packID:     1,
		recvInfo: recvInfo{
			recvID: 1,
		},
	}
	return a
}
