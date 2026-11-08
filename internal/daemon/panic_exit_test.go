// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestExitOnPanicSkipsCleanup(t *testing.T) {
	if os.Getenv("DAE_PANIC_EXIT_CHILD") != "" {
		defer fmt.Println("cleanup ran")
		defer exitOnPanic()
		panic("boom")
	}
	child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestExitOnPanicSkipsCleanup$")
	child.Env = append(os.Environ(), "DAE_PANIC_EXIT_CHILD=1")
	var stdout, stderr strings.Builder
	child.Stdout, child.Stderr = &stdout, &stderr
	err := child.Run()
	if exit, ok := errors.AsType[*exec.ExitError](err); !ok || exit.ExitCode() != 2 {
		t.Fatalf("panic exit = %v, want status 2", err)
	}
	if strings.Contains(stdout.String(), "cleanup ran") {
		t.Fatal("a panic ran the deferred cleanup")
	}
	if !strings.Contains(stderr.String(), "panic: boom") || !strings.Contains(stderr.String(), "TestExitOnPanicSkipsCleanup") {
		t.Fatalf("panic report lacks the value or the panicking stack:\n%s", stderr.String())
	}
}
