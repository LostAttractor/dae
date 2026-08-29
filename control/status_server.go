/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/samber/oops"
)

const statusSocketProbeTimeout = 250 * time.Millisecond

// StatusServer serves the runtime status of the current control plane over a
// unix socket. The listener outlives control-plane reloads; SetControlPlane
// swaps the plane the /status handler reads from.
type StatusServer struct {
	socketPath string
	version    string
	listener   net.Listener
	server     *http.Server
	mu         sync.RWMutex
	current    *ControlPlane
}

func StartStatusServer(socketPath string, version string) (*StatusServer, error) {
	listener, err := listenStatusSocket(socketPath)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to listen on status socket")
	}
	if err = os.Chmod(socketPath, 0600); err != nil {
		listener.Close()
		return nil, oops.Wrapf(err, "failed to chmod status socket")
	}
	s := &StatusServer{
		socketPath: socketPath,
		version:    version,
		listener:   listener,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/status", s.handleStatus)
	s.server = &http.Server{Handler: mux}
	go s.server.Serve(listener)
	return s, nil
}

// listenStatusSocket only removes an existing socket after proving that no
// process is listening on it. Other probe failures are treated conservatively
// so a starting daemon cannot disconnect an already-running instance.
func listenStatusSocket(socketPath string) (net.Listener, error) {
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
		return nil, fmt.Errorf("inspect existing status socket: %w", err)
	}
	if before.Mode()&os.ModeSocket == 0 {
		return nil, fmt.Errorf("status socket path is occupied by a non-socket file")
	}

	conn, probeErr := net.DialTimeout("unix", socketPath, statusSocketProbeTimeout)
	if probeErr == nil {
		_ = conn.Close()
		return nil, fmt.Errorf("status socket is already served by another process")
	}
	if !errors.Is(probeErr, syscall.ECONNREFUSED) {
		return nil, fmt.Errorf("probe existing status socket; refusing to remove it: %w", probeErr)
	}

	after, err := os.Lstat(socketPath)
	if err != nil {
		if os.IsNotExist(err) {
			return net.Listen("unix", socketPath)
		}
		return nil, fmt.Errorf("reinspect stale status socket: %w", err)
	}
	if !os.SameFile(before, after) {
		return nil, fmt.Errorf("status socket changed while checking whether it was stale")
	}
	if err = os.Remove(socketPath); err != nil {
		return nil, fmt.Errorf("remove stale status socket: %w", err)
	}
	return net.Listen("unix", socketPath)
}

func (s *StatusServer) SetControlPlane(c *ControlPlane) {
	s.mu.Lock()
	s.current = c
	s.mu.Unlock()
}

func (s *StatusServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	// Hold the read lock through snapshot construction. Setting the plane to
	// nil therefore also drains in-flight readers before the old plane closes.
	s.mu.RLock()
	c := s.current
	if c == nil {
		s.mu.RUnlock()
		http.Error(w, "control plane is reloading", http.StatusServiceUnavailable)
		return
	}
	snapshot, err := c.statusSnapshot(s.version)
	s.mu.RUnlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(snapshot); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *StatusServer) Close() {
	// Drain snapshot readers before the owning control plane is closed.
	s.SetControlPlane(nil)
	if s.server != nil {
		s.server.Close()
	}
	if s.listener != nil {
		s.listener.Close()
	}
	_ = os.Remove(s.socketPath)
}
