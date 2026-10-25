package netproxy

import (
	"testing"
	"time"
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

func TestDropRegistersEachPairOnce(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("registered a second counter for a direction and reason")
		}
	}()
	NewDrop(DropReceiveFull.Direction(), DropReceiveFull.Reason())
}
