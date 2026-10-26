package singmux

import (
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy/fq"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
)

func TestSmuxBlockedCarrierExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		local, remote := net.Pipe()
		defer remote.Close()
		s := newTestSmuxSession(local)
		defer s.abort()
		c, err := s.OpenStream(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write(make([]byte, 16<<10)); err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
		synctest.Wait()
		if s.drained() == nil {
			t.Fatal("blocked SYN/data/FIN was reported drained")
		}
		time.Sleep(netproxy.DialTimeout)
		synctest.Wait()
		if !s.IsClosed() || !errors.Is(s.err, os.ErrDeadlineExceeded) {
			t.Fatalf("carrier did not expire: %v", s.err)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.retired != 0 || len(s.streams) != 0 || s.fq.Queued() {
			t.Fatal("failed carrier retained send ownership")
		}
	})
}

func TestSmuxBatchUsesAvailablePoolCapacity(t *testing.T) {
	carrier := new(chunkRecordingCarrier)
	s := &smuxSession{conn: &monitoredConn{Conn: carrier}, wake: make(chan struct{}, 1)}
	s.frame.Store(smuxMaxFrame)
	s.fq.Release = putFrame
	defer s.fq.Clear()
	st := &smuxStream{session: s, id: 1}
	// Keep the sender stopped so one 32 KiB relay block and the next write
	// expose capacity fragmentation, independently of scheduling timing.
	st.writeDeadline = protocol.MakeDeadline()
	if _, err := st.Write(make([]byte, 32<<10)); err != nil {
		t.Fatal(err)
	}
	_ = st.SetWriteDeadline(time.Now().Add(time.Millisecond))
	n, err := st.Write(make([]byte, 32<<10))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("full queue: %d, %v", n, err)
	}
	batch := s.fq.Take(time.Now(), 128<<10, nil)
	defer s.fq.ReleaseBatch()
	wire := 0
	for _, frame := range batch {
		wire += len(frame)
	}
	if wire != fq.StreamLimit || st.flow.Buffered() != fq.StreamLimit || n < 30<<10 {
		t.Fatalf("wire=%d charged=%d next payload=%d", wire, st.flow.Buffered(), n)
	}
	if err := s.write(batch); err != nil {
		t.Fatal(err)
	}
	if carrier.largest != wire {
		t.Fatalf("carrier write=%d want=%d", carrier.largest, wire)
	}
}

type shortCarrier struct{ net.Conn }

func (*shortCarrier) Write(b []byte) (int, error)              { return len(b) - 1, nil }
func (*shortCarrier) WriteBuffers(batch [][]byte) (int, error) { return 0, nil }

func TestSmuxShortWriteFailsCarrier(t *testing.T) {
	for _, vector := range []bool{false, true} {
		carrier := new(shortCarrier)
		s := &smuxSession{conn: &monitoredConn{Conn: carrier}}
		if vector {
			s.buffers = carrier
		}
		if err := s.write([][]byte{{1, 2, 3}}); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("vector=%v error=%v", vector, err)
		}
	}
}

type deadlineCountingConn struct {
	net.Conn
	deadlines, writes atomic.Int32
}

func (c *deadlineCountingConn) SetWriteDeadline(t time.Time) error {
	c.deadlines.Add(1)
	return c.Conn.SetWriteDeadline(t)
}
func (c *deadlineCountingConn) Write(b []byte) (int, error) { c.writes.Add(1); return c.Conn.Write(b) }

func TestSmuxIdleSenderDoesNotEnterGate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		local, remote := net.Pipe()
		defer remote.Close()
		go io.Copy(io.Discard, remote)
		carrier := &deadlineCountingConn{Conn: local}
		s := newTestSmuxSession(carrier)
		defer s.abort()
		st, err := s.OpenStream(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		_ = st.Close()
		synctest.Wait()
		if deadlines, writes := carrier.deadlines.Load(), carrier.writes.Load(); writes == 0 || deadlines != writes {
			t.Fatalf("deadline/gate attempts=%d carrier writes=%d", deadlines, writes)
		}
		if s.drained() != nil {
			t.Fatal("empty sender did not become idle")
		}
	})
}
