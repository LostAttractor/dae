// SPDX-License-Identifier: AGPL-3.0-only

package handoff

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Children includes children created by every Go thread, not just the group leader.
func Children() (map[int]bool, error) {
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return nil, err
	}
	result := make(map[int]bool)
	read := false
	for _, task := range tasks {
		data, err := os.ReadFile(filepath.Join("/proc/self/task", task.Name(), "children"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		read = true
		for value := range strings.FieldsSeq(string(data)) {
			pid, err := strconv.Atoi(value)
			if err != nil {
				return nil, err
			}
			result[pid] = true
		}
	}
	if !read {
		return nil, errors.New("no process task children lists available (requires CONFIG_PROC_CHILDREN)")
	}
	return result, nil
}

// DrainChildren must run only after all owned Cmd.Wait calls finish and no new
// children can be started. The caller must already be a child subreaper.
// Residual descendants are always an error, even when successfully terminated.
// Cancellation skips the TERM grace period but still permits bounded kill/reap cleanup.
func DrainChildren(ctx context.Context) error {
	return drainChildren(ctx, Children)
}

func drainChildren(ctx context.Context, children func() (map[int]bool, error)) (resultErr error) {
	bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stop := ctx.Done()
	var canceled error
	tracked := make(map[int]int)
	defer func() {
		for _, fd := range tracked {
			// On failure, do not leave a known live child running while the caller exits.
			_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
			_ = unix.Close(fd)
		}
	}()
	var unexpected error
	defer func() { resultErr = errors.Join(unexpected, resultErr) }()
	grace := time.Now().Add(time.Second)
	forced := false
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if canceled == nil && ctx.Err() != nil {
			canceled = ctx.Err()
			stop = nil
			grace = time.Time{}
		}
		for pid, fd := range tracked {
			var info unix.Siginfo
			err := unix.Waitid(unix.P_PIDFD, fd, &info, unix.WEXITED|unix.WNOHANG|unix.WALL, nil)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil && !errors.Is(err, unix.ECHILD) {
				return fmt.Errorf("reap descendant: %w", err)
			}
			if info.Signo != 0 || errors.Is(err, unix.ECHILD) {
				_ = unix.Close(fd)
				delete(tracked, pid)
			}
		}
		// A childless process does not need CONFIG_PROC_CHILDREN to stop or exec.
		var info unix.Siginfo
		if err := unix.Waitid(unix.P_ALL, 0, &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT|unix.WALL, nil); errors.Is(err, unix.ECHILD) {
			if unexpected != nil {
				return canceled
			}
			return nil
		} else if errors.Is(err, unix.EINTR) {
			continue
		} else if err != nil {
			return fmt.Errorf("check for descendants: %w", err)
		}
		live, err := children()
		if err != nil {
			return err
		}
		if unexpected == nil {
			unexpected = errors.New("unexpected descendants after owned children were reaped")
		}
		for pid := range live {
			if _, ok := tracked[pid]; ok {
				continue
			}
			fd, err := unix.PidfdOpen(pid, 0)
			if errors.Is(err, unix.ESRCH) {
				continue
			}
			if err != nil {
				return fmt.Errorf("open descendant pidfd: %w", err)
			}
			// Verify parenthood after opening: the numeric PID from proc may have been reused.
			var info unix.Siginfo
			err = unix.Waitid(unix.P_PIDFD, fd, &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT|unix.WALL, nil)
			if err != nil {
				_ = unix.Close(fd)
				if errors.Is(err, unix.ECHILD) || errors.Is(err, unix.EINTR) {
					continue
				}
				return fmt.Errorf("validate descendant pidfd: %w", err)
			}
			tracked[pid] = fd
			sig := unix.SIGTERM
			if forced {
				sig = unix.SIGKILL
			}
			if err := unix.PidfdSendSignal(fd, sig, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
				return fmt.Errorf("terminate descendant: %w", err)
			}
		}
		if !forced && !time.Now().Before(grace) {
			forced = true
			for _, fd := range tracked {
				if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
					return fmt.Errorf("kill descendant: %w", err)
				}
			}
		}
		select {
		case <-bounded.Done():
			return errors.Join(canceled, fmt.Errorf("drain descendants: %w", bounded.Err()))
		case <-stop:
		case <-ticker.C:
		}
	}
}
