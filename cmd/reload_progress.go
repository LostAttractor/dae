// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/client/progress"
	"github.com/daeuniverse/dae/internal/handoff"
	"github.com/daeuniverse/dae/pkg/terminaltext"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// reloadProgress owns the command's display from connection setup to completion.
// Attaching a log pipe changes the source of progress, not the renderer.
type reloadProgress struct {
	*progress.Spinner
	kind         string
	output       *os.File
	logLine      func(string)
	pollStage    func(string)
	lastProgress string
	drain        func()
	stop         sync.Once
}

func newReloadProgress(stderr, stdout io.Writer, kind string) *reloadProgress {
	write, output := reloadLogOutput(stderr)
	spinner := progress.StartLive(output, "Connecting to the daemon...", func(frame string) (int, error) {
		// os.File.Write can wait for readiness even on a nonblocking terminal.
		n, err := unix.Write(int(output.Fd()), []byte(frame))
		if err == unix.EAGAIN || err == unix.EINTR {
			return 0, nil
		}
		return n, err
	})
	p := &reloadProgress{kind: kind, Spinner: spinner, output: output, logLine: write}
	if spinner.Enabled() {
		p.logLine = spinner.Println
		p.pollStage = spinner.Hint
	} else {
		// Remote reload and suspend retain their plain progress on stdout.
		p.pollStage = func(message string) { fmt.Fprintln(stdout, terminaltext.Line(message)) }
	}
	return p
}

func (p *reloadProgress) Stop() {
	p.stop.Do(func() {
		if p.drain != nil {
			p.drain()
		}
		p.Spinner.Stop()
		if p.output != nil {
			_ = p.output.Close()
		}
	})
}

func (p *reloadProgress) observe(status *api.Operation) {
	if status.Progress != "" {
		if status.Progress != p.lastProgress {
			p.pollStage(status.Progress)
		}
	} else if status.State == "queued" {
		p.Spinner.Hint("Queued for " + p.kind + "...")
	} else if status.State == "running" {
		p.Spinner.Hint("Waiting for " + p.kind + "...")
	}
	p.lastProgress = status.Progress
}

// The caller closes the writer after submission; stop drains and closes the reader.
func (p *reloadProgress) openLogPipe() (*os.File, error) {
	logs, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	polled := make(chan string, 1)
	if !p.Spinner.Enabled() {
		p.pollStage = func(message string) {
			select {
			case polled <- message:
			default:
			}
		}
	}
	var stopped atomic.Bool
	go func() {
		defer close(done)
		seen, staged := false, false
		lines := bufio.NewScanner(logs)
		for lines.Scan() && !stopped.Load() {
			seen = true
			line, stage := strings.CutPrefix(lines.Text(), handoff.StagePrefix)
			if stage && p.Spinner.Enabled() {
				staged = true
				p.Spinner.Update(line)
			} else {
				p.logLine(terminaltext.Plain(line))
			}
		}
		if staged {
			p.Spinner.Update("Waiting for daemon confirmation...")
		}
		if !seen && !p.Spinner.Enabled() {
			// Older daemons ignore the header and leave only polled stages.
			for message := range polled {
				if stopped.Load() {
					return
				}
				p.logLine(terminaltext.Line(message))
			}
		}
	}()
	p.drain = func() {
		close(polled)
		// Bound both the read and the wait: io.Writer need not support deadlines.
		_ = logs.SetReadDeadline(time.Now().Add(reloadPollInterval))
		select {
		case <-done:
		case <-time.After(reloadPollInterval):
			stopped.Store(true)
		}
		_ = logs.Close()
	}
	return writer, nil
}

func reloadLogOutput(out io.Writer) (write func(string), output *os.File) {
	write = func(line string) { _, _ = fmt.Fprintln(out, line) }
	file, ok := out.(*os.File)
	if !ok {
		return write, nil
	}
	discard := func(string) {}
	info, err := file.Stat()
	if err != nil {
		return discard, nil
	}
	mode := info.Mode().Type()
	if mode != os.ModeNamedPipe && mode != os.ModeSocket && mode&os.ModeCharDevice == 0 {
		return write, nil
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return discard, nil
	}
	if mode == os.ModeSocket {
		return func(line string) {
			_ = raw.Control(func(fd uintptr) {
				_, _ = unix.SendmsgN(int(fd), []byte(line+"\n"), nil, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL)
			})
		}, nil
	}
	// Use an independent pipe or terminal writer so the caller's flags stay
	// intact and a broken pipe cannot raise SIGPIPE on standard error.
	reopen := mode == os.ModeNamedPipe
	if err := raw.Control(func(fd uintptr) {
		reopen = reopen || term.IsTerminal(int(fd))
		if reopen {
			output, _ = os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", fd), os.O_WRONLY|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
		}
	}); err != nil {
		return discard, nil
	}
	if !reopen {
		return write, nil
	}
	if output == nil {
		return discard, nil
	}
	return func(line string) { handoff.WriteLog(output, []byte(line)) }, output
}
