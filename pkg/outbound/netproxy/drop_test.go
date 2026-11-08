package netproxy

import (
	"testing"
	"time"

	quic "github.com/daeuniverse/quic-go"
)

// A counter logs its first drop, then at most once a minute; a clock that
// went back does not silence it.
func TestDropLogsRateLimited(t *testing.T) {
	d := &Drop{direction: DropUpload, reason: t.Name()}
	d.Add(1)
	first := d.lastLog.Load()
	d.Add(2)
	if first == 0 || d.lastLog.Load() != first || d.Load() != 3 {
		t.Fatalf("logged at %d then %d with %d counted, want one log and 3", first, d.lastLog.Load(), d.Load())
	}
	future := time.Now().Add(time.Hour).UnixNano()
	d.lastLog.Store(future)
	d.Add(1)
	if d.lastLog.Load() >= future {
		t.Fatal("clock rollback suppressed drop logs")
	}
}

// A quiet counter counts without logging.
func TestQuietDropDoesNotLog(t *testing.T) {
	d := &Drop{direction: DropDownload, reason: t.Name(), quiet: true}
	d.Add(1)
	if d.lastLog.Load() != 0 || d.Load() != 1 {
		t.Fatalf("logged at %d with %d counted, want no log and 1", d.lastLog.Load(), d.Load())
	}
}

func TestDropRegistersEachTripleOnce(t *testing.T) {
	NewDrop("triple-test", DropUpload, DropUploadMemory.Reason())
	defer func() {
		if recover() == nil {
			t.Fatal("registered a second counter for a transport, direction and reason")
		}
	}()
	NewDrop(DropUploadMemory.Transport(), DropUploadMemory.Direction(), DropUploadMemory.Reason())
}

// quic-go's DATAGRAM drops reach the transport's counters, one per reason.
func TestQUICDatagramDropsAreCounted(t *testing.T) {
	drops := NewDatagramDrops("quic-test")
	for _, tc := range []struct {
		reason quic.DatagramDropReason
		drop   *Drop
	}{
		{quic.DatagramDropReceiveQueueFull, drops.ReceiveFull},
		{quic.DatagramDropTooLarge, drops.TooLarge},
		{quic.DatagramDropClosed, drops.carrierClosed},
	} {
		before := tc.drop.Load()
		drops.QUICDatagramDropped(tc.reason, 1200)
		if n := tc.drop.Load() - before; n != 1 {
			t.Fatalf("reason %d counted %d %s/%s drops, want 1", tc.reason, n, tc.drop.Direction(), tc.drop.Reason())
		}
	}
}
