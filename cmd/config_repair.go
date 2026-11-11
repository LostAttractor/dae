// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/daeuniverse/dae/config"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

func loadConfig(ctx context.Context, cmd *cobra.Command, path *string) (*config.Config, []string, error) {
	input, inputOK := cmd.InOrStdin().(*os.File)
	output, outputOK := cmd.ErrOrStderr().(*os.File)
	if !inputOK || !outputOK || !term.IsTerminal(int(input.Fd())) || !term.IsTerminal(int(output.Fd())) {
		return config.Load(*path)
	}
	var reader *bufio.Reader
	for {
		conf, includes, err := config.Load(*path)
		if err == nil {
			return conf, includes, nil
		}
		if cause := context.Cause(ctx); cause != nil {
			return nil, nil, cause
		}
		if reader == nil {
			// Reopen instead of duplicating: a nonblocking duplicate would also change stdin's flags.
			terminal, openErr := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", input.Fd()), os.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
			if openErr != nil {
				return nil, nil, fmt.Errorf("%w; open repair prompt input: %w", err, openErr)
			}
			defer terminal.Close()
			stop := context.AfterFunc(ctx, func() { _ = terminal.Close() })
			defer stop()
			reader = bufio.NewReader(terminal)
		}
		renamed, repaired, repairErr := repairConfigFile(ctx, reader, output, *path, err)
		if cause := context.Cause(ctx); cause != nil {
			return nil, nil, cause
		}
		if repairErr != nil {
			return nil, nil, fmt.Errorf("%w; repair config: %w", err, repairErr)
		}
		if !repaired {
			return nil, nil, err
		}
		if renamed != "" {
			*path = renamed
		}
	}
}

func repairConfigFile(ctx context.Context, input *bufio.Reader, output io.Writer, entry string, loadErr error) (renamed string, repaired bool, err error) {
	var path, question string
	if filenameErr, ok := errors.AsType[*config.InvalidFilenameError](loadErr); ok && filepath.Ext(filenameErr.Path) == "" {
		path = filenameErr.Path
		entry, err = filepath.Abs(entry)
		if err != nil {
			return "", false, err
		}
		if path != entry {
			return "", false, fmt.Errorf("cannot rename included config file %q; update its include references manually", path)
		}
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
			return "", false, nil
		}
		renamed = path + ".dae"
		question = fmt.Sprintf("Rename config file %q to %q?", path, renamed)
	} else if permissionErr, ok := errors.AsType[*config.UnsafePermissionsError](loadErr); ok {
		path = permissionErr.Path
		question = fmt.Sprintf("Change permissions of config file %q from %04o to 0600?", path, permissionErr.Mode.Perm())
	} else {
		return "", false, nil
	}
	if _, err := fmt.Fprintf(output, "%s [y/N]: ", question); err != nil {
		return "", false, err
	}
	answer, err := input.ReadString('\n')
	if cause := context.Cause(ctx); cause != nil {
		return "", false, cause
	}
	if errors.Is(err, io.EOF) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	if answer != "y" && answer != "yes" {
		return "", false, nil
	}
	if renamed != "" {
		err = unix.Renameat2(unix.AT_FDCWD, path, unix.AT_FDCWD, renamed, unix.RENAME_NOREPLACE)
	} else {
		err = os.Chmod(path, 0600)
	}
	return renamed, err == nil, err
}
