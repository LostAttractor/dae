// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/daeuniverse/dae/api"
	"golang.org/x/sys/unix"
)

var (
	ErrOperationsBusy   = errors.New("operation queue is full, a resource refresh is pending, or process replacement is in progress")
	ErrOperationsClosed = errors.New("daemon is stopping")
	ErrOperationInvalid = errors.New("invalid operation kind or abort option")
)

type OperationStore interface {
	SubmitOperation(api.OperationRequest) (api.Operation, error)
	Operation(string) (api.Operation, bool)
	ResourceRefreshStatus() api.ResourceRefreshStatus
}

func operationPath(path string) bool {
	return path == "/api/operations" || strings.HasPrefix(path, "/api/operations/") || path == "/api/resources" || path == "/api/resources/refresh"
}

func (s *handler) serveOperations(w http.ResponseWriter, r *http.Request, who caller) {
	if s.options.Operations == nil {
		apiError(w, http.StatusServiceUnavailable, "daemon operations are unavailable")
		return
	}
	if r.Method == http.MethodGet {
		if !apiBody(w, r, nil) {
			return
		}
		status, ok := s.options.Operations.Operation(r.PathValue("id"))
		if !ok {
			apiError(w, http.StatusNotFound, "operation is unknown or has expired")
			return
		}
		writeAPI(w, status)
		return
	}
	var request api.OperationRequest
	if apiBody(w, r, &request) {
		if request.ExecutablePID != 0 || request.Replace {
			peer, _ := r.Context().Value(peerCredentialsKey{}).(*unix.Ucred)
			if !localAPISocket(r) || peer == nil || peer.Uid != uint32(os.Geteuid()) || request.ExecutablePID <= 0 || int(peer.Pid) != request.ExecutablePID || request.Kind != "reload" {
				apiError(w, http.StatusForbidden, "executable replacement requires the authenticated local caller's PID")
				return
			}
			store, ok := s.options.Operations.(interface {
				SubmitExecutableOperation(api.OperationRequest, *os.File) (api.Operation, error)
			})
			if !ok {
				apiError(w, http.StatusServiceUnavailable, "executable replacement is unavailable")
				return
			}
			executable, err := os.Open(fmt.Sprintf("/proc/%d/exe", peer.Pid))
			if err != nil {
				apiError(w, http.StatusBadRequest, "cannot open caller executable")
				return
			}
			status, err := store.SubmitExecutableOperation(request, executable)
			if err != nil {
				_ = executable.Close()
			}
			writeOperationResult(w, status, err)
			return
		}
		s.submitOperation(w, request)
	}
}

func (s *handler) submitOperation(w http.ResponseWriter, request api.OperationRequest) {
	status, err := s.options.Operations.SubmitOperation(request)
	writeOperationResult(w, status, err)
}

func writeOperationResult(w http.ResponseWriter, status api.Operation, err error) {
	if err != nil {
		code := http.StatusInternalServerError
		switch {
		case errors.Is(err, ErrOperationsBusy):
			code = http.StatusConflict
		case errors.Is(err, ErrOperationsClosed):
			code = http.StatusServiceUnavailable
		case errors.Is(err, ErrOperationInvalid):
			code = http.StatusBadRequest
		}
		apiError(w, code, err.Error())
		return
	}
	writeAPIStatus(w, status, http.StatusAccepted)
}
