package congestion

import (
	"github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/congestion/bbr"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/congestion/brutal"
	"github.com/daeuniverse/quic-go"
)

func UseBBR(conn *quic.Conn) {
	conn.SetCongestionControl(bbr.NewBBRv3Sender(
		bbr.DefaultClock{},
		bbr.GetInitialPacketSize(conn.RemoteAddr()),
	))
}

func UseBrutal(conn *quic.Conn, tx uint64) error {
	sender, err := brutal.NewBrutalSender(tx)
	if err != nil {
		return err
	}
	conn.SetCongestionControl(sender)
	return nil
}
