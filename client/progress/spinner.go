// SPDX-License-Identifier: AGPL-3.0-only

// Package progress renders transient feedback while a CLI operation is waiting.
package progress

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/jedib0t/go-pretty/v6/text"
	"golang.org/x/term"
)

const (
	showDelay     = 150 * time.Millisecond
	frameInterval = 80 * time.Millisecond
	clearLine     = "\r\x1b[2K"
)

var frames = [...]string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Spinner owns one terminal line until Stop returns. Callers must stop it before
// printing other output to that terminal. The zero value is disabled.
type Spinner struct {
	mu      sync.Mutex
	message string
	stop    chan struct{}
	done    chan struct{}
	once    sync.Once
}

// Start animates only when w is a terminal and TERM is not dumb. Quick operations
// finish without displaying anything. Call Stop on every return path.
func Start(w io.Writer, message string) *Spinner {
	f, ok := w.(*os.File)
	if !ok || os.Getenv("TERM") == "dumb" || !term.IsTerminal(int(f.Fd())) {
		return new(Spinner)
	}
	return start(w, message, func() int {
		width, _, err := term.GetSize(int(f.Fd()))
		if err != nil || width <= 0 {
			return 80
		}
		return width
	})
}

func start(w io.Writer, message string, width func() int) *Spinner {
	s := &Spinner{stop: make(chan struct{}), done: make(chan struct{})}
	s.Update(message)
	go s.run(w, width)
	return s
}

// Enabled reports whether terminal feedback is available, including during the
// initial delay. Callers can otherwise print ordinary progress lines.
func (s *Spinner) Enabled() bool { return s.done != nil }

// Update replaces the current stage without starting another animation.
func (s *Spinner) Update(message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.message = strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, message)), " ")
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

func (s *Spinner) run(w io.Writer, width func() int) {
	defer close(s.done)
	delay := time.NewTimer(showDelay)
	defer delay.Stop()
	select {
	case <-s.stop:
		return
	case <-delay.C:
	}
	ticker := time.NewTicker(frameInterval)
	defer ticker.Stop()
	defer io.WriteString(w, clearLine)
	for frame := 0; ; frame = (frame + 1) % len(frames) {
		s.mu.Lock()
		message := s.message
		s.mu.Unlock()
		// Leave the final column unused to avoid wrapping into another line.
		line := text.Trim(frames[frame]+" "+message, max(0, width()-1))
		if _, err := fmt.Fprint(w, clearLine, line); err != nil {
			return
		}
		select {
		case <-s.stop:
			return
		case <-ticker.C:
		}
	}
}
