//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/config"
	"golang.org/x/sys/unix"
)

func configRepairTerminal(t *testing.T, answers string) *os.File {
	t.Helper()
	master, slave := openTestPTY(t)
	if err := slave.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(master, answers); err != nil {
		t.Fatal(err)
	}
	return slave
}

func openTestPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { master.Close() })
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { slave.Close() })
	return master, slave
}

func writeRepairConfig(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte("global {}\nrouting { fallback: direct }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRepairsConfig(t *testing.T) {
	for _, test := range []struct {
		name, suffix, answers string
		mode                  os.FileMode
		include               bool
		symlink               bool
		relative              bool
	}{
		{name: "rename", answers: "y\n", mode: 0600},
		{name: "relative rename", answers: "y\n", mode: 0600, relative: true},
		{name: "permissions", suffix: ".dae", answers: "YES\n", mode: 0644},
		{name: "rename then permissions", answers: "y\nyes\n", mode: 0644},
		{name: "include permissions", suffix: ".dae", answers: "y\n", mode: 0660, include: true},
		{name: "symlink rename then permissions", answers: "y\ny\n", mode: 0644, symlink: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config"+test.suffix)
			writeRepairConfig(t, path, test.mode)
			entry := path
			if test.symlink {
				target := filepath.Join(filepath.Dir(path), "target.dae")
				if err := os.Rename(path, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Base(target), path); err != nil {
					t.Fatal(err)
				}
			}
			if test.include {
				child := filepath.Join(filepath.Dir(path), "child.dae")
				if err := os.Rename(path, child); err != nil {
					t.Fatal(err)
				}
				path = child
				if err := os.WriteFile(entry, []byte("include { child.dae }\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			terminal := configRepairTerminal(t, test.answers)
			command := newValidateCommand(nil)
			command.SetIn(terminal)
			command.SetErr(terminal)
			entryArg := entry
			if test.relative {
				t.Chdir(filepath.Dir(entry))
				entryArg = filepath.Base(entry)
			}
			command.SetArgs([]string{"-c", entryArg})
			if err := command.ExecuteContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			if test.suffix == "" {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("old config path still exists: %v", err)
				}
				path += ".dae"
				entry = path
			}
			if got, _ := command.Flags().GetString("config"); got != entry {
				t.Fatalf("config path = %q, want %q", got, entry)
			}
			if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("permissions were not repaired: %v, %v", info, err)
			}
			if test.symlink {
				if target, err := os.Readlink(path); err != nil || target != "target.dae" {
					t.Fatalf("repair replaced the symlink: %q, %v", target, err)
				}
			}
			if _, _, err := config.Load(entry); err != nil {
				t.Fatalf("repaired config is invalid: %v", err)
			}
		})
	}
}

func TestConfigRepairRequiresExplicitConsent(t *testing.T) {
	for _, suffix := range []string{"", ".dae"} {
		for _, answer := range []string{"\n", "n\n", "no\n", "invalid\n", "", "y"} {
			t.Run(fmt.Sprintf("%s/%q", suffix, answer), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "config"+suffix)
				writeRepairConfig(t, path, 0644)
				_, _, loadErr := config.Load(path)
				var output bytes.Buffer
				renamed, repaired, err := repairConfigFile(t.Context(), bufio.NewReader(strings.NewReader(answer)), &output, path, loadErr)
				if err != nil || repaired || renamed != "" {
					t.Fatalf("unconfirmed repair: renamed=%q repaired=%v err=%v", renamed, repaired, err)
				}
				if !strings.Contains(output.String(), "[y/N]") {
					t.Fatalf("confirmation prompt missing: %q", &output)
				}
				if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0644 {
					t.Fatalf("unconfirmed repair changed file: %v, %v", info, err)
				}
			})
		}
	}
}

func TestConfigRepairSkipsUnsupportedPaths(t *testing.T) {
	for _, name := range []string{"directory", "missing", "existing.conf", "multiple.conf.bak"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			switch name {
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "missing":
			default:
				writeRepairConfig(t, path, 0600)
			}
			_, _, loadErr := config.Load(path)
			var output bytes.Buffer
			renamed, repaired, err := repairConfigFile(t.Context(), bufio.NewReader(strings.NewReader("yes\n")), &output, path, loadErr)
			if err != nil || repaired || renamed != "" || output.Len() != 0 {
				t.Fatalf("unsupported path prompted or repaired: %q, %v, %v, %q", renamed, repaired, err, &output)
			}
		})
	}
}

func TestConfigRepairRefusesIncludedFileRename(t *testing.T) {
	dir := t.TempDir()
	entry := filepath.Join(dir, "config.dae")
	child := filepath.Join(dir, "child")
	content := "include { child }\nglobal {}\nrouting { fallback: block }\n"
	if err := os.WriteFile(entry, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	writeRepairConfig(t, child, 0600)
	loadErr := fmt.Errorf("load include: %w", &config.InvalidFilenameError{Path: child})
	var output bytes.Buffer
	renamed, repaired, err := repairConfigFile(t.Context(), bufio.NewReader(strings.NewReader("yes\n")), &output, entry, loadErr)
	if err == nil || !strings.Contains(err.Error(), "included config") || repaired || renamed != "" || output.Len() != 0 {
		t.Fatalf("included file rename was not refused: %q, %v, %v, %q", renamed, repaired, err, &output)
	}
	if _, err := os.Stat(child); err != nil {
		t.Fatalf("included file was moved: %v", err)
	}
	if _, err := os.Stat(child + ".dae"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rename destination exists: %v", err)
	}
	if got, err := os.ReadFile(entry); err != nil || string(got) != content {
		t.Fatalf("main config changed: %q, %v", got, err)
	}
}

func TestConfigRenamePreservesExistingDestination(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	writeRepairConfig(t, path, 0600)
	target := path + ".dae"
	if err := os.WriteFile(target, []byte("keep me"), 0600); err != nil {
		t.Fatal(err)
	}
	_, _, loadErr := config.Load(path)
	_, repaired, err := repairConfigFile(t.Context(), bufio.NewReader(strings.NewReader("yes\n")), io.Discard, path, loadErr)
	if repaired || !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing target was not rejected: repaired=%v err=%v", repaired, err)
	}
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("source file was moved: %v, %v", info, err)
	}
	if content, err := os.ReadFile(target); err != nil || string(content) != "keep me" {
		t.Fatalf("destination content changed: %q, %v", content, err)
	}
}

func TestConfigRepairRequiresBothTerminals(t *testing.T) {
	for _, name := range []string{"piped input", "redirected output", "regular input file"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.dae")
			writeRepairConfig(t, path, 0644)
			terminal := configRepairTerminal(t, "yes\n")
			command := newValidateCommand(nil)
			command.SetIn(terminal)
			command.SetErr(terminal)
			var output bytes.Buffer
			switch name {
			case "piped input":
				command.SetIn(strings.NewReader("yes\n"))
			case "redirected output":
				command.SetErr(&output)
			case "regular input file":
				input, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer input.Close()
				command.SetIn(input)
			}
			_, _, err := loadConfig(t.Context(), command, &path)
			if _, ok := errors.AsType[*config.UnsafePermissionsError](err); !ok {
				t.Fatalf("non-interactive load lost validation error: %v", err)
			}
			if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0644 || output.Len() != 0 {
				t.Fatalf("non-interactive load prompted or changed file: %v, %v, %q", info, err, &output)
			}
		})
	}
}

func TestConfigRepairPromptCanceled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.dae")
	writeRepairConfig(t, path, 0644)
	master, terminal := openTestPTY(t)
	command := newValidateCommand(nil)
	command.SetIn(terminal)
	command.SetErr(terminal)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := loadConfig(ctx, command, &path)
		done <- err
	}()
	if err := master.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	prompt, err := bufio.NewReader(master).ReadString(']')
	if err != nil || !strings.HasSuffix(prompt, "[y/N]") {
		t.Fatalf("repair prompt not received: %q, %v", prompt, err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("repair returned %v, want cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("repair prompt did not stop after cancellation")
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0644 {
		t.Fatalf("canceled repair changed file: %v, %v", info, err)
	}
	if _, err := terminal.Stat(); err != nil {
		t.Fatalf("canceled repair closed the caller's terminal: %v", err)
	}
}
