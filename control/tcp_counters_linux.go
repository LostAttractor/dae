// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// tcpWriteCounter observes payload accepted by a native TCP socket. It must be
// created before the first application write, and retired before CloseWrite.
// RawConn keeps the descriptor alive during each sample, including concurrent
// Close; retaining a bare descriptor would risk observing an unrelated socket.
func tcpWriteCounter(conn *net.TCPConn) (func() (uint64, error), error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var baseline uint64
	var probeErr error
	err = raw.Control(func(fd uintptr) {
		protocol, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PROTOCOL)
		if err != nil {
			probeErr = err
			return
		}
		if protocol != unix.IPPROTO_TCP {
			probeErr = errors.New("payload counter requires native TCP")
			return
		}
		info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if err != nil {
			probeErr = err
			return
		}
		baseline = info.Bytes_acked
		queued, err := unix.IoctlGetInt(int(fd), unix.SIOCOUTQ)
		if err != nil {
			probeErr = err
		} else if queued != 0 {
			probeErr = errors.New("TCP socket already has pending writes")
		}
	})
	if err = errors.Join(err, probeErr); err != nil {
		return nil, err
	}
	return func() (uint64, error) {
		var count uint64
		var sampleErr error
		err := raw.Control(func(fd uintptr) {
			// Read acknowledgements FIRST. An ACK between these calls can
			// temporarily undercount, but cannot count a byte twice. The
			// owner retains the high watermark and settles the exact total
			// from io.Copy before sending FIN.
			info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
			if err != nil {
				sampleErr = err
				return
			}
			queued, err := unix.IoctlGetInt(int(fd), unix.SIOCOUTQ)
			if err != nil {
				sampleErr = err
				return
			}
			if queued < 0 || info.Bytes_acked < baseline {
				sampleErr = fmt.Errorf("invalid TCP counters: acked=%d baseline=%d queued=%d", info.Bytes_acked, baseline, queued)
				return
			}
			count = info.Bytes_acked - baseline + uint64(queued)
		})
		return count, errors.Join(err, sampleErr)
	}, nil
}
