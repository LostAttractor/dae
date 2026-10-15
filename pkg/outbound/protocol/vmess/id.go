package vmess

import (
	"crypto/md5"
	"github.com/google/uuid"
)

func commandKey(id uuid.UUID) [16]byte {
	data := append(id[:], []byte("c48619fe-8f02-49e0-b9e9-edf763e17e21")...)
	return md5.Sum(data)
}
