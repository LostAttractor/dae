/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"sync/atomic"

	"github.com/samber/oops"
)

// StatusServer serves the runtime status of the current control plane over a
// unix socket. The listener outlives control-plane reloads; SetControlPlane
// swaps the plane the /status handler reads from.
type StatusServer struct {
	socketPath string
	version    string
	listener   net.Listener
	server     *http.Server
	current    atomic.Pointer[ControlPlane]
}

func StartStatusServer(socketPath string, version string) (*StatusServer, error) {
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return nil, oops.Wrapf(err, "failed to remove stale status socket")
	}
	listener, err := net.Listen("unix", socketPath)
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

func (s *StatusServer) SetControlPlane(c *ControlPlane) {
	s.current.Store(c)
}

func (s *StatusServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	c := s.current.Load()
	if c == nil {
		http.Error(w, "control plane is reloading", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(c.StatusSnapshot(s.version)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *StatusServer) Close() {
	if s.server != nil {
		s.server.Close()
	}
	if s.listener != nil {
		s.listener.Close()
	}
	_ = os.Remove(s.socketPath)
}
