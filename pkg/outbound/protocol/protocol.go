package protocol

import "errors"

var (
	ErrFailAuth     = errors.New("fail to authenticate")
	ErrReplayAttack = errors.New("replay attack")
)
