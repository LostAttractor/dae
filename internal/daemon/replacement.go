// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/internal/apiserver"
	"github.com/daeuniverse/dae/internal/handoff"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const replacementEnv = "DAE_EXEC_FD"
const replacementTimeout = 3 * time.Minute

type replacementManifest struct {
	Protocol             int
	PID                  int
	ProcessName          string
	Deadline             time.Time
	CutoverAt            time.Time
	Operation            api.Operation
	Files                map[string]int
	Links                []control.ReplacementLink
	HostIndex, PeerIndex int
	LAN, WAN             []string
}

type replacementState struct {
	manifest replacementManifest
	files    map[string]*os.File
}

func readReplacement(value string) (_ *replacementState, resultErr error) {
	fd, err := strconv.Atoi(value)
	if err != nil {
		return nil, errors.New("invalid exec state descriptor")
	}
	file, err := handoff.InheritedFile(fd, "exec-state")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	state := &replacementState{files: make(map[string]*os.File)}
	defer func() {
		if resultErr != nil {
			state.close()
		}
	}()
	if err := handoff.ReadState(file, &state.manifest); err != nil {
		return nil, err
	}
	m := state.manifest
	if m.Protocol != handoff.Protocol || m.PID != os.Getpid() || !m.Deadline.After(time.Now()) || m.CutoverAt.IsZero() || m.CutoverAt.After(time.Now()) {
		return nil, errors.New("invalid replacement identity or deadline")
	}
	if m.Operation.ID == "" || m.Operation.Kind != "reload" || m.Operation.State != "running" || m.HostIndex <= 0 || m.PeerIndex <= 0 || m.HostIndex == m.PeerIndex {
		return nil, errors.New("invalid replacement operation or topology")
	}
	used := map[int]bool{fd: true}
	for name, resourceFD := range m.Files {
		if used[resourceFD] || !replacementResource(name, len(m.Links)) {
			return nil, errors.New("invalid inherited resource descriptor")
		}
		used[resourceFD] = true
		resource, err := handoff.InheritedFile(resourceFD, name)
		if err != nil {
			return nil, err
		}
		state.files[name] = resource
		if err := validateReplacementResource(name, resource); err != nil {
			return nil, fmt.Errorf("inherited %s: %w", name, err)
		}
	}
	for _, name := range []string{"lock", "hostns", "daens", "local", "inputs"} {
		if state.files[name] == nil {
			return nil, fmt.Errorf("missing inherited %s", name)
		}
	}
	for i := range m.Links {
		if state.files[fmt.Sprintf("link/%d", i)] == nil {
			return nil, errors.New("missing inherited attachment")
		}
	}
	if err := validateDaemonLock(state.files["lock"]); err != nil {
		return nil, err
	}
	return state, nil
}

func replacementResource(name string, links int) bool {
	switch name {
	case "lock", "hostns", "daens", "local", "management", "inputs":
		return true
	}
	kind, value, ok := strings.Cut(name, "/")
	if !ok {
		return false
	}
	n, err := strconv.Atoi(value)
	return err == nil && strconv.Itoa(n) == value && (kind == "link" && n >= 0 && n < links || kind == "observe" && n > 0 && n <= 65535)
}

func validateReplacementResource(name string, file *os.File) error {
	fd := int(file.Fd())
	switch {
	case name == "inputs":
		_, err := handoff.SealedFileSize(file, resource.MaxInputArchiveBytes)
		return err
	case name == "hostns" || name == "daens":
		kind, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
		if err != nil || kind != unix.CLONE_NEWNET {
			return errors.Join(errors.New("not a network namespace"), err)
		}
	case name == "local" || name == "management" || strings.HasPrefix(name, "observe/"):
		kind, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
		if err != nil || kind != unix.SOCK_STREAM {
			return errors.Join(errors.New("not a stream listener"), err)
		}
		accepting, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
		if err != nil || accepting != 1 {
			return errors.Join(errors.New("socket is not listening"), err)
		}
		address, err := unix.Getsockname(fd)
		if err != nil {
			return err
		}
		_, local := address.(*unix.SockaddrUnix)
		if local != (name == "local") {
			return errors.New("listener address family differs")
		}
	}
	return nil
}

func (s *replacementState) close() {
	if s == nil {
		return
	}
	for _, file := range s.files {
		_ = file.Close()
	}
	clear(s.files)
}

func (s *replacementState) take(name string) *os.File {
	if s == nil {
		return nil
	}
	file := s.files[name]
	delete(s.files, name)
	return file
}

func (s *replacementState) takeLinks(count int) ([]*os.File, error) {
	files := make([]*os.File, count)
	for i := range count {
		file := s.take(fmt.Sprintf("link/%d", i))
		if file == nil {
			for j := range i {
				_ = files[j].Close()
			}
			return nil, errors.New("missing inherited BPF link")
		}
		files[i] = file
	}
	return files, nil
}

func (s *replacementState) takeObservability() (map[uint16]*os.File, error) {
	inherited := make(map[uint16]*os.File)
	var firstErr error
	for name, file := range s.files {
		value, ok := strings.CutPrefix(name, "observe/")
		if !ok {
			continue
		}
		delete(s.files, name)
		if firstErr != nil {
			_ = file.Close()
			continue
		}
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			_ = file.Close()
			firstErr = err
			continue
		}
		inherited[uint16(port)] = file
	}
	if firstErr != nil {
		closeObservabilityFiles(inherited)
		return nil, firstErr
	}
	return inherited, nil
}

// Release a retired wildcard binding before observability binds any loopback port.
func (s *replacementState) takeManagement(port uint16) (*apiserver.Server, error) {
	file := s.take("management")
	if file == nil {
		return nil, nil
	}
	defer file.Close()
	if port == 0 {
		return nil, nil
	}
	server, err := apiserver.FromFile(file, "tcp")
	if err != nil {
		return nil, err
	}
	if server.Addr().(*net.TCPAddr).Port != int(port) {
		server.Close()
		return nil, nil
	}
	return server, nil
}

func (a *application) replace(ctx context.Context, id string, executable *os.File) (_ string, resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, replacementTimeout)
	defer cancel()
	if a.options.Startup == nil || a.options.Startup.lock == nil {
		return "", errors.New("replacement requires the daemon startup resources")
	}
	if err := a.operations.beginReplacement(); err != nil {
		return "", err
	}
	defer a.operations.endReplacement()
	a.report("Checking replacement executable...")
	preparedInputs, err := a.preflightReplacement(ctx, executable)
	if err != nil {
		return "", err
	}
	defer func() {
		if preparedInputs != nil {
			_ = preparedInputs.Close()
		}
	}()
	snapshot, err := a.datapath.ExportReplacement(ctx)
	if err != nil {
		return "", err
	}
	defer snapshot.Release()
	deadline, _ := ctx.Deadline()
	status, _ := a.operations.Operation(id)
	ns := control.GetDaeNetns()
	manifest := replacementManifest{Protocol: handoff.Protocol, PID: os.Getpid(), Deadline: deadline,
		ProcessName: control.CurrentProcessIdentity().Name,
		Operation:   status, Files: make(map[string]int), Links: snapshot.Links,
		HostIndex: ns.Dae0().Attrs().Index, PeerIndex: ns.Dae0Peer().Attrs().Index,
		LAN: a.conf.Global.LanInterface, WAN: a.conf.Global.WanInterface}
	var files []*os.File
	defer func() {
		for _, file := range files {
			_ = file.Close()
		}
	}()
	add := func(name string, file *os.File) {
		manifest.Files[name] = int(file.Fd())
		files = append(files, file)
	}
	add("inputs", preparedInputs)
	preparedInputs = nil // The exec descriptor set now owns it.
	duplicate := func(name string, fd int) error {
		file, err := handoff.Dup(fd, name)
		if err == nil {
			add(name, file)
		}
		return err
	}
	if err := duplicate("lock", int(a.options.Startup.lock.Fd())); err != nil {
		return "", err
	}
	host, dae := ns.NamespaceFDs()
	if err := duplicate("hostns", host); err != nil {
		return "", err
	}
	if err := duplicate("daens", dae); err != nil {
		return "", err
	}
	for name, server := range map[string]*apiserver.Server{"local": a.localAPI, "management": a.managementAPI} {
		if server == nil {
			continue
		}
		file, err := server.File()
		if err != nil {
			return "", err
		}
		add(name, file)
	}
	observability, err := exportObservability()
	if err != nil {
		return "", err
	}
	for port, file := range observability {
		add(fmt.Sprintf("observe/%d", port), file)
	}
	for i, file := range snapshot.TakeFiles() {
		add(fmt.Sprintf("link/%d", i), file)
	}
	manifest.CutoverAt = time.Now()
	state, err := handoff.SealState(manifest)
	if err != nil {
		return "", err
	}
	files = append(files, state)
	blocked := false
	defer func() {
		if blocked {
			resultErr = &activationError{errors.Join(resultErr, errors.New("replacement failed after blocking captured traffic"))}
		}
	}()
	for _, server := range []*apiserver.Server{a.localAPI, a.managementAPI} {
		if server == nil {
			continue
		}
		resume, err := server.Pause(ctx)
		if err != nil {
			return "", err
		}
		defer func() {
			if !blocked {
				resume()
			}
		}()
	}
	a.report("Blocking captured traffic and closing old connections...")
	if err := snapshot.Block(ctx); err != nil {
		return "", err
	}
	blocked = true
	ns.SetOwnership(false)
	a.localAPI.SetOwnership(false)
	a.beginShutdown()
	a.resolver.SetRoute(nil)
	if err := exit(a.datapath, a.localAPI, a.managementAPI); err != nil {
		return "", err
	}
	if err := handoff.DrainChildren(ctx); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if a.options.Startup.signals.Stop() {
		return "", errors.New("replacement interrupted by a stop signal")
	}
	env := replacementEnvironment(replacementEnv, int(state.Fd()))
	args := append([]string{"dae"}, a.options.LaunchArgs...)
	return "", handoff.Exec(executable, args, env, files)
}

func (a *application) finishStartup(ctx context.Context) error {
	if err := a.datapath.ConfirmReady(func() error {
		startup := a.options.Startup
		if startup.incoming != nil {
			// Transfer the original deadline to the last write; it must not cancel
			// the running daemon after systemd has accepted READY.
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, startup.incoming.manifest.Deadline)
			defer cancel()
			startup.stopPreparation()
		}
		return notifyService(ctx, "ready")
	}); err != nil {
		a.beginShutdown()
		return errors.Join(fmt.Errorf("finish startup: %w", err), a.datapath.GoOffline())
	}
	if a.staging {
		control.GetDaeNetns().SetOwnership(true)
		a.localAPI.SetOwnership(true)
		a.staging = false
	}
	return nil
}

func replacementEnvironment(marker string, fd int) []string {
	env := slices.DeleteFunc(os.Environ(), func(entry string) bool {
		key, _, _ := strings.Cut(entry, "=")
		return key == replacementEnv || key == preflightEnv
	})
	return append(env, marker+"="+strconv.Itoa(fd))
}

// Keeping the zombie reserves its PID when revocation could not be confirmed.
type exemptionError struct{ error }

func (e *exemptionError) Unwrap() error { return e.error }

func (a *application) preflightReplacement(ctx context.Context, executable *os.File) (_ *os.File, resultErr error) {
	started := time.Now()
	inputs, err := handoff.NewSealableFile("dae-prepared-inputs")
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			_ = inputs.Close()
		}
	}()
	channel, childSocket, err := handoff.SocketPair()
	if err != nil {
		return nil, err
	}
	defer channel.Close()
	defer childSocket.Close()
	deadline, _ := ctx.Deadline()
	_ = channel.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = channel.Close() })
	defer stop()
	command := exec.CommandContext(ctx, "/proc/self/fd/3", a.options.LaunchArgs...)
	command.ExtraFiles = []*os.File{executable, childSocket, a.options.Startup.lock, inputs}
	command.Env = replacementEnvironment(preflightEnv, 4)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	allowed := false
	defer func() {
		var revoke func() error
		if allowed {
			revoke = func() error { return a.datapath.SetReplacementPID(0) }
		}
		if err := stopReplacementCandidate(command, revoke); err != nil {
			resultErr = &activationError{errors.Join(resultErr, err)}
		}
	}()
	if err := command.Start(); err != nil {
		return nil, err
	}
	_ = childSocket.Close()
	var hello preflightHello
	if err := channel.Receive(&hello); err != nil {
		return nil, fmt.Errorf("replacement preflight identity: %w", err)
	}
	if hello.Error != "" {
		return nil, errors.New(hello.Error)
	}
	if hello.Protocol != handoff.Protocol || hello.KernelPID == 0 {
		return nil, errors.New("invalid replacement preflight identity")
	}
	if err := a.datapath.SetReplacementPID(hello.KernelPID); err != nil {
		return nil, err
	}
	allowed = true
	if err := channel.Send(preflightRequest{Protocol: handoff.Protocol, Parent: os.Getpid(), Deadline: deadline, LAN: a.conf.Global.LanInterface, WAN: a.conf.Global.WanInterface, Identity: control.CurrentProcessIdentity(), SelectorHints: a.plane.PreparationSelectorHints()}); err != nil {
		return nil, err
	}
	var result preflightResult
	if err := channel.Receive(&result); err != nil {
		return nil, fmt.Errorf("replacement preflight: %w", err)
	}
	if err := a.datapath.SetReplacementPID(0); err != nil {
		return nil, &activationError{&exemptionError{err}}
	}
	allowed = false
	if err := channel.Send(struct{}{}); err != nil {
		return nil, err
	}
	if err := command.Wait(); err != nil {
		return nil, fmt.Errorf("replacement preflight exit: %w", err)
	}
	if result.Error != "" {
		return nil, errors.New(result.Error)
	}
	size, err := handoff.SealedFileSize(inputs, resource.MaxInputArchiveBytes)
	if err != nil {
		return nil, fmt.Errorf("replacement prepared inputs: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	log.WithFields(log.Fields{"duration": time.Since(started), "bytes": size}).Info("Replacement inputs prepared")
	return inputs, nil
}

// Revocation precedes Wait: an exempt PID must not be reused by another process.
func stopReplacementCandidate(command *exec.Cmd, revoke func() error) error {
	var err error
	if revoke != nil {
		if revokeErr := revoke(); revokeErr != nil {
			err = &exemptionError{revokeErr}
		}
	}
	if command.Process == nil || command.ProcessState != nil {
		return err
	}
	// The preflight owns this process group; normal business workers do not.
	if killErr := unix.Kill(-command.Process.Pid, unix.SIGKILL); killErr != nil && !errors.Is(killErr, unix.ESRCH) {
		err = errors.Join(err, killErr)
	}
	if killErr := command.Process.Kill(); killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
		return errors.Join(err, killErr)
	}
	if err != nil {
		return err
	}
	if err := command.Wait(); err != nil {
		if _, exited := errors.AsType[*exec.ExitError](err); !exited {
			return err
		}
	}
	return nil
}
