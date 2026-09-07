// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

func listenUnix(path string) (net.Listener, error) {
	listener, err := bindUnix(path)
	if err != nil {
		return nil, fmt.Errorf("listen on API socket: %w", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("chmod API socket: %w", err)
	}
	return listener, nil
}

// bindUnix only removes an existing socket after proving that no
// process is listening on it. Other probe failures are treated conservatively
// so a starting daemon cannot disconnect an already-running instance.
func bindUnix(socketPath string) (net.Listener, error) {
	listener, listenErr := net.Listen("unix", socketPath)
	if listenErr == nil {
		return listener, nil
	}
	if !errors.Is(listenErr, syscall.EADDRINUSE) {
		return nil, listenErr
	}

	before, err := os.Lstat(socketPath)
	if err != nil {
		if os.IsNotExist(err) {
			return net.Listen("unix", socketPath)
		}
		return nil, fmt.Errorf("inspect existing API socket: %w", err)
	}
	if before.Mode()&os.ModeSocket == 0 {
		return nil, fmt.Errorf("API socket path is occupied by a non-socket file")
	}

	conn, probeErr := net.DialTimeout("unix", socketPath, 250*time.Millisecond)
	if probeErr == nil {
		_ = conn.Close()
		return nil, fmt.Errorf("API socket is already served by another process")
	}
	if !errors.Is(probeErr, syscall.ECONNREFUSED) {
		return nil, fmt.Errorf("probe existing API socket; refusing to remove it: %w", probeErr)
	}

	after, err := os.Lstat(socketPath)
	if err != nil {
		if os.IsNotExist(err) {
			return net.Listen("unix", socketPath)
		}
		return nil, fmt.Errorf("reinspect stale API socket: %w", err)
	}
	if !os.SameFile(before, after) {
		return nil, fmt.Errorf("API socket changed while checking whether it was stale")
	}
	if err = os.Remove(socketPath); err != nil {
		return nil, fmt.Errorf("remove stale API socket: %w", err)
	}
	return net.Listen("unix", socketPath)
}
