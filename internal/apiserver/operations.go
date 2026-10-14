// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"errors"
	"net/http"
	"strings"

	"github.com/daeuniverse/dae/api"
)

var (
	ErrOperationsBusy   = errors.New("operation queue is full or a resource refresh is already pending")
	ErrOperationsClosed = errors.New("daemon is stopping")
	ErrOperationInvalid = errors.New("invalid operation kind, abort option, or expected PID")
	ErrOperationPID     = errors.New("the API daemon does not match the requested PID")
)

type OperationStore interface {
	SubmitOperation(api.OperationRequest) (api.Operation, error)
	Operation(string) (api.Operation, bool)
	ResourceRefreshStatus() api.ResourceRefreshStatus
}

func operationPath(path string) bool {
	return path == "/api/operations" || strings.HasPrefix(path, "/api/operations/") || path == "/api/resources" || path == "/api/resources/refresh"
}

func (s *handler) serveOperations(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
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
		s.submitOperation(w, request)
	}
}

func (s *handler) submitOperation(w http.ResponseWriter, request api.OperationRequest) {
	status, err := s.options.Operations.SubmitOperation(request)
	if err != nil {
		code := http.StatusInternalServerError
		switch {
		case errors.Is(err, ErrOperationsBusy), errors.Is(err, ErrOperationPID):
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
