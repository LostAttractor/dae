package singmux

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

// Sequential Close must not turn a blocked carrier into an unlimited queue.
func TestSmuxRetiredAdmissionAndDelivery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		local, remote := net.Pipe()
		defer remote.Close()
		s := newTestSmuxSession(local)
		defer s.abort()
		payload := bytes.Repeat([]byte{0x5a}, 16<<10)
		for i := range smuxRetiredLimit {
			c, err := s.OpenStream(t.Context())
			if err != nil {
				t.Fatalf("open %d: %v", i, err)
			}
			_ = c.SetWriteDeadline(time.Now().Add(time.Millisecond))
			if n, err := c.Write(payload); n != len(payload) || err != nil {
				t.Fatal(n, err)
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
		}
		synctest.Wait()
		if _, err := s.OpenStream(t.Context()); !errors.Is(err, errSmuxRetired) {
			t.Fatalf("unbounded replacement of closed streams: %v", err)
		}
		s.mu.Lock()
		retired, owned, overfull := s.retired, len(s.streams), 0
		for _, st := range s.streams {
			if st.flow.Full(0) {
				overfull++
			}
		}
		s.mu.Unlock()
		if retired != smuxRetiredLimit || owned != retired || overfull != 0 {
			t.Fatalf("retired=%d owners=%d over StreamLimit=%d", retired, owned, overfull)
		}
		frames := readFrames(remote)
		data := make(map[uint32][]byte)
		for remaining := retired; remaining > 0; {
			f := nextFrame(t, frames)
			switch f.cmd {
			case smuxCmdPSH:
				data[f.sid] = append(data[f.sid], f.data...)
			case smuxCmdFIN:
				if !bytes.Equal(data[f.sid], payload) {
					t.Fatalf("stream %d lost accepted tail: %d bytes", f.sid, len(data[f.sid]))
				}
				remaining--
			}
		}
		synctest.Wait()
		s.mu.Lock()
		retired, owned = s.retired, len(s.streams)
		s.mu.Unlock()
		if retired != 0 || owned != 0 {
			t.Fatalf("drained owners=%d retired=%d", owned, retired)
		}
		c, err := s.OpenStream(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	})
}
