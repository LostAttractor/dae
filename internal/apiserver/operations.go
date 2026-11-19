// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/internal/handoff"
	"golang.org/x/sys/unix"
)

type OperationStore interface {
	SubmitOperation(api.OperationRequest) (api.Operation, error)
	Operation(string) (api.Operation, bool)
	ResourceRefreshStatus() api.ResourceRefreshStatus
}

func operationPath(path string) bool {
	return path == "/api/operations" || strings.HasPrefix(path, "/api/operations/") || path == "/api/resources" || path == "/api/resources/refresh"
}

func localServicePath(path string) bool {
	return operationPath(path) || monitoringPath(path)
}

func (s *Handler) serveOperations(w http.ResponseWriter, r *http.Request, who caller) {
	if s.options.Operations == nil {
		apiError(w, http.StatusServiceUnavailable, "daemon operations are unavailable")
		return
	}
	if r.Method == http.MethodPost {
		var request api.OperationRequest
		if apiBody(w, r, &request) {
			if request.ExecutablePID != 0 || request.ExecutableFD != 0 || request.Replace {
				s.submitLocalReload(w, r, request)
			} else {
				s.submitOperation(w, request)
			}
		}
		return
	}
	if !apiBody(w, r, nil) {
		return
	}
	status, ok := s.options.Operations.Operation(r.PathValue("id"))
	if !ok {
		apiError(w, http.StatusNotFound, "operation is unknown or has expired")
		return
	}
	writeAPI(w, status)
}

func (s *Handler) submitLocalReload(w http.ResponseWriter, r *http.Request, request api.OperationRequest) {
	peer, _ := r.Context().Value(peerCredentialsKey{}).(*unix.Ucred)
	if !localAPISocket(r) || peer == nil || peer.Uid != uint32(os.Geteuid()) || request.ExecutablePID <= 0 || int(peer.Pid) != request.ExecutablePID || request.Kind != "reload" {
		apiError(w, http.StatusForbidden, "executable replacement requires the authenticated local caller's PID")
		return
	}
	store, ok := s.options.Operations.(interface {
		SubmitExecutableOperation(api.OperationRequest, *os.File) (api.Operation, error)
	})
	if !ok {
		apiError(w, http.StatusServiceUnavailable, "local reload with executable selection is unavailable")
		return
	}
	var executable *os.File
	var err error
	if request.ExecutableFD != 0 {
		if request.ExecutableFD < 3 {
			apiError(w, http.StatusBadRequest, "invalid caller executable descriptor")
			return
		}
		executable, err = handoff.OpenExecutable(fmt.Sprintf("/proc/%d/fd/%d", peer.Pid, request.ExecutableFD))
		request.Replace = true
	} else {
		executable, err = os.Open(fmt.Sprintf("/proc/%d/exe", peer.Pid))
	}
	if err != nil {
		apiError(w, http.StatusBadRequest, "cannot use caller executable: "+err.Error())
		return
	}
	status, err := store.SubmitExecutableOperation(request, executable)
	if err != nil {
		_ = executable.Close()
	}
	writeOperationResult(w, status, err)
}

func (s *Handler) submitOperation(w http.ResponseWriter, request api.OperationRequest) {
	status, err := s.options.Operations.SubmitOperation(request)
	writeOperationResult(w, status, err)
}

func writeOperationResult(w http.ResponseWriter, status api.Operation, err error) {
	if err != nil {
		code := http.StatusInternalServerError
		switch {
		case errors.Is(err, api.ErrOperationsBusy):
			code = http.StatusConflict
		case errors.Is(err, api.ErrOperationsClosed):
			code = http.StatusServiceUnavailable
		case errors.Is(err, api.ErrOperationInvalid):
			code = http.StatusBadRequest
		}
		apiError(w, code, err.Error())
		return
	}
	writeAPIStatus(w, status, http.StatusAccepted)
}
