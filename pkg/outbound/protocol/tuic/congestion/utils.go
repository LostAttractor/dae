package congestion

import (
	"github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/congestion/bbr"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/congestion/brutal"
	"github.com/daeuniverse/quic-go"
	quiccongestion "github.com/daeuniverse/quic-go/congestion"
)

func UseBBR(conn *quic.Conn) {
	// quic-go replays the connection's current datagram size on installation.
	conn.SetCongestionControl(bbr.NewBBRv3Sender(bbr.DefaultClock{}, quiccongestion.InitialPacketSize))
}

func UseBrutal(conn *quic.Conn, tx uint64) error {
	sender, err := brutal.NewBrutalSender(tx)
	if err != nil {
		return err
	}
	conn.SetCongestionControl(sender)
	return nil
}
