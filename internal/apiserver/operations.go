// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
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
			logFDValues := r.Header.Values(api.ReloadLogFDHeader)
			if request.ExecutablePID != 0 || request.ExecutableFD != 0 || request.Replace || len(logFDValues) != 0 {
				s.submitLocalReload(w, r, request, logFDValues)
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

func (s *Handler) submitLocalReload(w http.ResponseWriter, r *http.Request, request api.OperationRequest, logFDValues []string) {
	peer, _ := r.Context().Value(peerCredentialsKey{}).(*unix.Ucred)
	if !localAPISocket(r) || peer == nil || peer.Uid != uint32(os.Geteuid()) || request.ExecutablePID <= 0 || int(peer.Pid) != request.ExecutablePID || request.Kind != "reload" {
		apiError(w, http.StatusForbidden, "executable replacement and log streaming require an authenticated local reload with the caller's PID")
		return
	}
	var logFD int
	if len(logFDValues) != 0 {
		fd, err := strconv.Atoi(logFDValues[0])
		if len(logFDValues) != 1 || err != nil || fd < 3 || strconv.Itoa(fd) != logFDValues[0] {
			apiError(w, http.StatusBadRequest, "invalid caller log descriptor")
			return
		}
		logFD = fd
	}
	store, ok := s.options.Operations.(interface {
		SubmitExecutableOperation(api.OperationRequest, *os.File, *os.File) (api.Operation, error)
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
	var logPipe *os.File
	if logFD != 0 {
		logPipe, err = openLogPipe(peer.Pid, logFD)
		if err != nil {
			_ = executable.Close()
			apiError(w, http.StatusBadRequest, "cannot open caller log pipe")
			return
		}
	}
	status, err := store.SubmitExecutableOperation(request, executable, logPipe)
	if err != nil {
		_ = executable.Close()
		if logPipe != nil {
			_ = logPipe.Close()
		}
	}
	writeOperationResult(w, status, err)
}

func openLogPipe(pid int32, fd int) (*os.File, error) {
	// Pin and validate before opening for writes. Reopening with an independent
	// file description keeps the caller from clearing O_NONBLOCK on our writer.
	path, err := os.OpenFile(fmt.Sprintf("/proc/%d/fd/%d", pid, fd), unix.O_PATH, 0)
	if err != nil {
		return nil, err
	}
	defer path.Close()
	if err := handoff.ValidateAnonymousPipe(path); err != nil {
		return nil, err
	}
	return os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", path.Fd()), os.O_WRONLY|unix.O_NONBLOCK, 0)
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
