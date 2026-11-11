package direct

import (
	"errors"
	"fmt"
	"sync/atomic"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// TCP_RTO_MAX_MS, added in Linux 6.15; not yet in our minimum x/sys version.
const tcpRTOMaxMS = 44

var maxRTOReported atomic.Bool

func setMaxRTO(c syscall.RawConn, timeout time.Duration) error {
	// MPTCP rejects this option even after falling back to TCP.
	if rawProtocol(c) == unix.IPPROTO_MPTCP {
		return nil
	}
	var sockErr error
	if err := c.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, tcpRTOMaxMS, int(timeout.Milliseconds()))
	}); err != nil {
		return err
	}
	if errors.Is(sockErr, unix.ENOPROTOOPT) {
		if maxRTOReported.CompareAndSwap(false, true) {
			log.Warn("TCP_RTO_MAX_MS unavailable; node connections use kernel retransmission defaults")
		}
		return nil
	}
	if sockErr != nil {
		return fmt.Errorf("set TCP_RTO_MAX_MS: %w", sockErr)
	}
	return nil
}
