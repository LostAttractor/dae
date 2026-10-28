package tls

import (
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/protocol"
)

func parseRange(value string, lower, upper int64) (int64, int64, error) {
	left, right, ok := strings.Cut(value, "-")
	if !ok {
		return 0, 0, fmt.Errorf("invalid range: %s", value)
	}
	min, err := strconv.ParseInt(left, 10, 64)
	if err != nil {
		return 0, 0, err
	}
	max, err := strconv.ParseInt(right, 10, 64)
	if err != nil {
		return 0, 0, err
	}
	if min < lower || max < min || max > upper {
		return 0, 0, fmt.Errorf("range %q must satisfy %d <= min <= max <= %d", value, lower, upper)
	}
	return min, max, nil
}

type FragmentConfig struct {
	minLength, maxLength     int64
	minInterval, maxInterval int64
}

func ParseFragmentConfig(length, interval string) (*FragmentConfig, error) {
	minLength, maxLength, err := parseRange(length, 1, math.MaxInt64)
	if err != nil {
		return nil, fmt.Errorf("TLS fragment length: %w", err)
	}
	minInterval, maxInterval, err := parseRange(interval, 0, math.MaxInt64/int64(time.Millisecond))
	if err != nil {
		return nil, fmt.Errorf("TLS fragment interval: %w", err)
	}
	return &FragmentConfig{minLength, maxLength, minInterval, maxInterval}, nil
}

func (c *FragmentConfig) Wrap(conn net.Conn) net.Conn {
	return &FragmentConn{Conn: conn, config: c, closed: make(chan struct{}), writeDeadline: protocol.MakeDeadline()}
}

type FragmentConn struct {
	net.Conn
	config        *FragmentConfig
	closed        chan struct{}
	closeOnce     sync.Once
	writeDeadline protocol.Deadline
}

func (f *FragmentConn) Close() error {
	f.closeOnce.Do(func() { close(f.closed) })
	f.writeDeadline.Set(time.Time{})
	return f.Conn.Close()
}

func (f *FragmentConn) SetDeadline(t time.Time) error {
	if err := f.Conn.SetDeadline(t); err != nil {
		return err
	}
	f.writeDeadline.Set(t)
	return nil
}

func (f *FragmentConn) SetWriteDeadline(t time.Time) error {
	if err := f.Conn.SetWriteDeadline(t); err != nil {
		return err
	}
	f.writeDeadline.Set(t)
	return nil
}

func (f *FragmentConn) Write(b []byte) (n int, err error) {
	if len(b) <= 5 || b[0] != 22 {
		return f.Conn.Write(b)
	}
	recordLen := 5 + ((int(b[3]) << 8) | int(b[4]))
	if len(b) < recordLen {
		return f.Conn.Write(b)
	}
	data := b[5:recordLen]
	buf := make([]byte, 5+int(min(int64(len(data)), f.config.maxLength)))
	var hello []byte
	for from := 0; ; {
		length := min(int64(len(data)-from), randBetween(f.config.minLength, f.config.maxLength))
		to := from + int(length)
		copy(buf[:3], b)
		copy(buf[5:], data[from:to])
		l := to - from
		from = to
		buf[3] = byte(l >> 8)
		buf[4] = byte(l)
		if f.config.maxInterval == 0 {
			hello = append(hello, buf[:5+l]...)
		} else {
			if _, err := f.Conn.Write(buf[:5+l]); err != nil {
				return 0, err
			}
			if from < len(data) {
				timer := time.NewTimer(time.Duration(randBetween(f.config.minInterval, f.config.maxInterval)) * time.Millisecond)
				select {
				case <-timer.C:
				case <-f.closed:
					err = net.ErrClosed
				case <-f.writeDeadline.Wait():
					err = os.ErrDeadlineExceeded
				}
				timer.Stop()
				if err != nil {
					return 0, err
				}
			}
		}
		if from == len(data) {
			break
		}
	}
	if len(hello) > 0 {
		if _, err := f.Conn.Write(hello); err != nil {
			return 0, err
		}
	}
	if len(b) > recordLen {
		if _, err := f.Conn.Write(b[recordLen:]); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}
