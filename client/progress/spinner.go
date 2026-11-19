// SPDX-License-Identifier: AGPL-3.0-only

// Package progress renders transient feedback while a CLI operation is waiting.
package progress

import (
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/pkg/terminaltext"
	"github.com/jedib0t/go-pretty/v6/text"
	"golang.org/x/term"
)

const (
	showDelay     = 150 * time.Millisecond
	frameInterval = 80 * time.Millisecond
	clearLine     = "\r\x1b[2K"
)

var frames = [...]string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Spinner owns one terminal line until Stop returns. Use Println for logs above
// the animation. The zero value is disabled.
type Spinner struct {
	mu       sync.Mutex
	message  string
	hasStage bool
	lines    chan string
	stop     chan struct{}
	done     chan struct{}
	once     sync.Once
}

// Start animates only when w is a terminal and TERM is not dumb. Quick operations
// finish without displaying anything. Call Stop on every return path.
func Start(w io.Writer, message string) *Spinner {
	f, _ := w.(*os.File)
	return startTerminal(f, message, f.WriteString, showDelay)
}

// StartLive animates immediately alongside streamed logs. The frame writer
// targets f and may drop frames under backpressure.
func StartLive(f *os.File, message string, write func(string) (int, error)) *Spinner {
	return startTerminal(f, message, write, 0)
}

func startTerminal(f *os.File, message string, write func(string) (int, error), delay time.Duration) *Spinner {
	if f == nil || os.Getenv("TERM") == "dumb" || !term.IsTerminal(int(f.Fd())) {
		return new(Spinner)
	}
	return start(write, message, delay, func() int {
		width, _, err := term.GetSize(int(f.Fd()))
		if err != nil || width <= 0 {
			return 80
		}
		return width
	})
}

func start(write func(string) (int, error), message string, delay time.Duration, width func() int) *Spinner {
	s := &Spinner{lines: make(chan string), stop: make(chan struct{}), done: make(chan struct{})}
	s.Hint(message)
	go s.run(write, width, delay)
	return s
}

// Enabled reports whether terminal feedback is available, including during the
// initial delay. Callers can otherwise print ordinary progress lines.
func (s *Spinner) Enabled() bool { return s.done != nil }

// Update replaces the current stage without starting another animation.
func (s *Spinner) Update(message string) {
	s.setStage(message, true)
}

// Hint displays best-effort status until an authoritative Update arrives.
func (s *Spinner) Hint(message string) {
	s.setStage(message, false)
}

func (s *Spinner) setStage(message string, authoritative bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if authoritative || !s.hasStage {
		s.hasStage = authoritative
		s.message = strings.Join(strings.Fields(terminaltext.Line(message)), " ")
	}
}

// Println inserts one already-sanitized log line into the terminal scrollback.
func (s *Spinner) Println(line string) {
	if s.Enabled() {
		select {
		case s.lines <- line:
		case <-s.done:
		}
	}
}

// Stop clears the line and waits for the renderer to exit. It is safe to call
// more than once, including from a deferred cleanup after an explicit Stop.
func (s *Spinner) Stop() {
	if !s.Enabled() {
		return
	}
	s.once.Do(func() { close(s.stop) })
	<-s.done
}

func (s *Spinner) run(write func(string) (int, error), width func() int, delay time.Duration) {
	defer close(s.done)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	frame := -1
	defer func() {
		if frame >= 0 {
			_, _ = write(clearLine)
		}
	}()
	status := func() string {
		s.mu.Lock()
		defer s.mu.Unlock()
		// Leave the final column unused to avoid wrapping into another line.
		return text.Trim(frames[frame]+" "+s.message, max(0, width()-1))
	}
	for {
		var output string
		select {
		case <-s.stop:
			return
		case line := <-s.lines:
			output = line + "\n"
			if frame >= 0 {
				output = clearLine + output + status()
			}
		case <-timer.C:
			frame = (frame + 1) % len(frames)
			output = clearLine + status()
			timer.Reset(frameInterval)
		}
		if _, err := write(output); err != nil {
			return
		}
	}
}
