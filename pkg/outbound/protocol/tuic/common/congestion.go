package common

import (
	"github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/congestion"
	"github.com/daeuniverse/quic-go"
)

const (
	InitialStreamReceiveWindow     = 2 * 1024 * 1024  // 2 MB
	MaxStreamReceiveWindow         = 32 * 1024 * 1024 // 32 MB
	InitialConnectionReceiveWindow = 32 * 1024 * 1024 // 32 MB
	MaxConnectionReceiveWindow     = 64 * 1024 * 1024 // 64 MB
)

func SetCongestionController(quicConn *quic.Conn, cc string, cwnd int) {
	switch cc {
	default:
		fallthrough
	case "bbr":
		congestion.UseBBR(quicConn)
	}
}
