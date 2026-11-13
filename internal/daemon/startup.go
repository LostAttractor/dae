// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/common/selector"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/internal/handoff"
	"golang.org/x/sys/unix"
)

const preflightEnv = "DAE_PREFLIGHT_FD"

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
			s.Close()
		}
	}()
	resume, hasResume := os.LookupEnv(replacementEnv)
	probe, hasProbe := os.LookupEnv(preflightEnv)
	_ = os.Unsetenv(replacementEnv)
	_ = os.Unsetenv(preflightEnv)
	if hasResume && hasProbe {
		return nil, errors.New("conflicting inherited startup descriptors")
	}
	switch {
	case hasResume:
		s.incoming, err = readReplacement(resume)
		if err != nil {
			return nil, err
		}
		s.lock = s.incoming.take("lock")
		s.setPreparationDeadline(s.incoming.manifest.Deadline)
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

func (s *Startup) Context() context.Context { return s.ctx }

func (s *Startup) Resuming() bool { return s.incoming != nil }

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
	Protocol  int
	KernelPID uint32
	Error     string
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
	hello := preflightHello{Protocol: handoff.Protocol, KernelPID: kernelPID}
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
