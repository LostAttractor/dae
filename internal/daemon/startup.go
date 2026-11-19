// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/common/selector"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/internal/handoff"
	"github.com/daeuniverse/dae/pkg/terminaltext"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const preflightEnv = "DAE_PREFLIGHT_FD"
const preflightLogEnv = "DAE_PREFLIGHT_LOG_FD"
const preflightLogFD = 7

// Startup owns process resources before configuration or business initialization.
type Startup struct {
	lock               *os.File
	signals            *handoff.Signals
	ctx                context.Context
	cancel             context.CancelCauseFunc
	beginShutdown      func()
	stopWatchdog       func()
	incoming           *replacementState
	preflight          *handoff.Channel
	preflightInputs    *os.File
	logPipe            *os.File
	stopLogMirror      func()
	inputs             *resource.Inputs
	preparation        *time.Timer
	preparationExpired chan struct{}
}

func newStartup() *Startup {
	s := &Startup{signals: handoff.NewSignals()}
	s.ctx, s.cancel = context.WithCancelCause(s.signals.Context())
	// One shutdown budget covers configuration I/O, business teardown and exec.
	s.beginShutdown, s.stopWatchdog = watchShutdown(s.ctx, shutdownTimeout, func() {
		_, _ = fmt.Fprintln(os.Stderr, "Shutdown timed out; forcing process exit")
		os.Exit(1)
	})
	return s
}

func OpenStartup() (_ *Startup, err error) {
	s := newStartup()
	defer func() {
		if err != nil {
			s.ReportInitializationError(err)
			s.Close()
		}
	}()
	resume, hasResume := os.LookupEnv(replacementEnv)
	probe, hasProbe := os.LookupEnv(preflightEnv)
	probeLog, hasProbeLog := os.LookupEnv(preflightLogEnv)
	_ = os.Unsetenv(replacementEnv)
	_ = os.Unsetenv(preflightEnv)
	_ = os.Unsetenv(preflightLogEnv)
	if hasResume && hasProbe || hasProbeLog && !hasProbe {
		return nil, errors.New("conflicting inherited startup descriptors")
	}
	switch {
	case hasResume:
		s.incoming, err = readReplacement(resume)
		if err != nil {
			return nil, err
		}
		s.lock = s.incoming.take("lock")
		s.logPipe = s.incoming.take("logs")
		s.stage("Starting replacement daemon...")
		s.setPreparationDeadline(s.incoming.manifest.Deadline)
		if err := restoreProcessName(s.incoming.manifest.ProcessName); err != nil {
			return nil, err
		}
		inputs := s.incoming.take("inputs")
		s.inputs, err = readPreparedInputs(s.ctx, inputs)
		_ = inputs.Close()
		if err != nil {
			return nil, fmt.Errorf("read prepared inputs: %w", err)
		}
	case hasProbe:
		fd, parseErr := strconv.Atoi(probe)
		if parseErr != nil || fd != 4 {
			return nil, errors.New("invalid preflight descriptor")
		}
		file, openErr := handoff.InheritedFile(fd, "preflight")
		if openErr != nil {
			return nil, openErr
		}
		defer file.Close()
		kind, typeErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
		if typeErr != nil || kind != unix.SOCK_STREAM {
			return nil, errors.New("preflight descriptor is not a stream socket")
		}
		credentials, credErr := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
		if credErr != nil || credentials.Pid != int32(os.Getppid()) || credentials.Uid != uint32(os.Geteuid()) {
			return nil, errors.New("preflight channel does not belong to the parent")
		}
		if hasProbeLog {
			if probeLog != strconv.Itoa(preflightLogFD) {
				return nil, errors.New("invalid preflight log descriptor")
			}
			s.logPipe, err = inheritLogPipe(preflightLogFD)
			if err != nil {
				return nil, fmt.Errorf("preflight logs: %w", err)
			}
		}
		s.preflight, err = handoff.FromFile(file)
		if err != nil {
			return nil, err
		}
		s.lock, err = handoff.InheritedFile(5, "preflight-lock")
		if err != nil {
			return nil, err
		}
		if err := validateDaemonLock(s.lock); err != nil {
			return nil, err
		}
		s.preflightInputs, err = handoff.InheritedFile(6, "preflight-inputs")
		if err != nil {
			return nil, err
		}
		if err := validateEmptyInputFile(s.preflightInputs); err != nil {
			return nil, err
		}
		_ = unix.Close(3)
	default:
		s.lock, err = AcquireLock()
		if err != nil {
			return nil, err
		}
	}
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return nil, fmt.Errorf("enable descendant cleanup: %w", err)
	}
	return s, nil
}

// FD-based exec names the new image after the descriptor. Write the group leader's
// comm: PR_SET_NAME would only rename whichever Go thread runs this goroutine.
func restoreProcessName(name string) error {
	if name == "" || len(name) > 15 || strings.ContainsRune(name, 0) {
		return errors.New("invalid inherited process name")
	}
	if err := os.WriteFile("/proc/self/comm", []byte(name), 0600); err != nil {
		return fmt.Errorf("restore daemon process name: %w", err)
	}
	return nil
}

func (s *Startup) Context() context.Context { return s.ctx }

func (s *Startup) Resuming() bool { return s.incoming != nil }

func (s *Startup) stage(message string) {
	if s.logPipe != nil {
		handoff.WriteStage(s.logPipe, message)
	}
}

func inheritLogPipe(fd int) (*os.File, error) {
	file, err := handoff.InheritedFile(fd, "startup-logs")
	if err != nil {
		return nil, err
	}
	if err := handoff.ValidateLogPipe(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

type startupLogFormatter struct {
	log.Formatter
	pipe *os.File
}

func (f startupLogFormatter) Format(entry *log.Entry) ([]byte, error) {
	data, err := f.Formatter.Format(entry)
	if err == nil {
		handoff.WriteLog(f.pipe, data)
	}
	return data, err
}

// MirrorLogs leaves the daemon's regular output writer and formatting intact.
func (s *Startup) MirrorLogs() {
	if s.logPipe == nil {
		return
	}
	base := log.StandardLogger().Formatter
	s.stopLogMirror = func() { log.SetFormatter(base) }
	log.SetFormatter(startupLogFormatter{Formatter: base, pipe: s.logPipe})
}

func writeReplacementError(pipe *os.File, stage string, err error) {
	if pipe != nil && err != nil {
		handoff.WriteLog(pipe, []byte(stage+": "+terminaltext.Line(resource.RedactError(err).Error())))
	}
}

// ReportInitializationError covers failures before the API can serve status.
func (s *Startup) ReportInitializationError(err error) {
	if err != nil {
		writeReplacementError(s.logPipe, "Initialization failed", err)
		s.closeLogPipe()
	}
}

func (s *Startup) closeLogPipe() {
	if s.stopLogMirror != nil {
		s.stopLogMirror()
		s.stopLogMirror = nil
	}
	if s.logPipe != nil {
		_ = s.logPipe.Close()
		s.logPipe = nil
	}
}

func (s *Startup) setPreparationDeadline(deadline time.Time) {
	expired := make(chan struct{})
	s.preparationExpired = expired
	s.preparation = time.AfterFunc(max(time.Until(deadline), 0), func() {
		s.beginShutdown()
		s.cancel(context.DeadlineExceeded)
		close(expired)
	})
}

func (s *Startup) stopPreparation() {
	if s.preparation == nil {
		return
	}
	if !s.preparation.Stop() {
		<-s.preparationExpired
	}
	s.preparation = nil
	s.preparationExpired = nil
}

func (s *Startup) Close() {
	if s == nil {
		return
	}
	s.closeLogPipe()
	s.stopPreparation()
	s.cancel(context.Canceled)
	s.signals.Stop()
	if s.preflight != nil {
		_ = s.preflight.Close()
	}
	if s.preflightInputs != nil {
		_ = s.preflightInputs.Close()
	}
	s.inputs = nil
	s.incoming.close()
	if s.lock != nil {
		_ = s.lock.Close()
	}
	if s.stopWatchdog != nil {
		s.stopWatchdog()
		s.stopWatchdog = nil
	}
}

type preflightRequest struct {
	Protocol      int
	Parent        int
	Deadline      time.Time
	LAN, WAN      []string
	Identity      control.ProcessIdentity
	SelectorHints map[string]*selector.Path
}

type preflightHello struct {
	Protocol    int
	KernelPID   uint32
	Error       string
	StartupLogs bool `json:",omitzero"`
}

type preflightResult struct {
	Error string
}

// Preflight uses the target's parser and capability checks, not a second Runtime.
func (s *Startup) Preflight(path string, definitions map[string]plugin.Definition) (bool, error) {
	if s.preflight == nil {
		return false, nil
	}
	channel := s.preflight
	_ = channel.SetDeadline(time.Now().Add(replacementTimeout))
	kernelPID, identityErr := control.KernelProcessID()
	hello := preflightHello{Protocol: handoff.Protocol, KernelPID: kernelPID, StartupLogs: s.logPipe != nil}
	if identityErr != nil {
		hello.Error = identityErr.Error()
	}
	if err := channel.Send(hello); err != nil {
		return true, err
	}
	if identityErr != nil {
		return true, identityErr
	}
	var request preflightRequest
	if err := channel.Receive(&request); err != nil {
		return true, err
	}
	if request.Protocol != handoff.Protocol || request.Parent != os.Getppid() || !request.Deadline.After(time.Now()) {
		return true, errors.New("invalid preflight request")
	}
	_ = channel.SetDeadline(request.Deadline)
	ctx, cancel := context.WithDeadline(s.ctx, request.Deadline)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = channel.Close() })
	defer stop()
	// EOF cancels probes if the owner disappears. The release also holds our PID
	// until the parent has revoked its temporary datapath exemption.
	released := make(chan error, 1)
	go func() {
		var release struct{}
		err := channel.Receive(&release)
		cancel()
		released <- err
	}()
	check := func() error {
		inputs, err := prepareReplacementInputs(ctx, path, request, definitions)
		if err != nil {
			return err
		}
		if err := inputs.Encode(s.preflightInputs); err != nil {
			return err
		}
		return handoff.SealFile(s.preflightInputs)
	}
	result := preflightResult{}
	if err := check(); err != nil {
		result.Error = err.Error()
	}
	if err := handoff.DrainChildren(ctx); err != nil {
		if result.Error != "" {
			err = errors.Join(errors.New(result.Error), err)
		}
		result.Error = err.Error()
	}
	if err := channel.Send(result); err != nil {
		return true, err
	}
	return true, <-released
}

func notifyService(ctx context.Context, state string) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	address := os.Getenv("NOTIFY_SOCKET")
	if address == "" {
		return nil
	}
	var message string
	switch state {
	case "ready":
		message = "READY=1"
	case "reloading":
		var ts unix.Timespec
		if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
			return err
		}
		message = fmt.Sprintf("RELOADING=1\nMONOTONIC_USEC=%d", ts.Nano()/1000)
	case "stopping":
		message = "STOPPING=1"
	default:
		return fmt.Errorf("unknown service notification %q", state)
	}
	ctx, cancel := context.WithTimeout(ctx, shutdownTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unixgram", address)
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := context.Cause(ctx); err != nil {
		return err
	}
	_, err = conn.Write([]byte(message))
	if err != nil {
		return errors.Join(err, context.Cause(ctx))
	}
	return nil
}
