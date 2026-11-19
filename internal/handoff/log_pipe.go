// SPDX-License-Identifier: AGPL-3.0-only

package handoff

import (
	"bytes"
	"errors"
	"os"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// StagePrefix marks a progress record; formatted daemon logs strip this control byte.
const StagePrefix = "\x1e"

func WriteStage(file *os.File, message string) {
	WriteLog(file, []byte(StagePrefix+message))
}

func ValidateAnonymousPipe(file *os.File) error {
	if file == nil {
		return errors.New("missing log pipe")
	}
	fd := int(file.Fd())
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		return err
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return err
	}
	if info.Mode&unix.S_IFMT != unix.S_IFIFO || fs.Type != unix.PIPEFS_MAGIC {
		return errors.New("log descriptor is not an anonymous pipe")
	}
	return nil
}

func ValidateLogPipe(file *os.File) error {
	if err := ValidateAnonymousPipe(file); err != nil {
		return err
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil {
		return err
	}
	if flags&(unix.O_ACCMODE|unix.O_NONBLOCK) != unix.O_WRONLY|unix.O_NONBLOCK {
		return errors.New("log pipe must be write-only and nonblocking")
	}
	return nil
}

// WriteLog mirrors one record to a validated writer. A full or abandoned pipe
// cannot slow down startup or prevent the daemon from writing its usual logs.
func WriteLog(file *os.File, line []byte) {
	if file == nil || len(line) == 0 {
		return
	}
	const pipeBuf = 4096 // Linux PIPE_BUF: writes up to this size are atomic.
	const truncated = " ... [log entry truncated]\n"
	terminated := line[len(line)-1] == '\n'
	if len(line) > pipeBuf || len(line) == pipeBuf && !terminated {
		end := pipeBuf - len(truncated)
		for limit := end - (utf8.UTFMax - 1); end > limit && !utf8.RuneStart(line[end]); {
			end--
		}
		line = append(bytes.Clone(line[:end]), truncated...)
	} else if !terminated {
		line = append(bytes.Clone(line), '\n')
	}
	raw, err := file.SyscallConn()
	if err == nil {
		_ = raw.Control(func(fd uintptr) { _, _ = unix.Write(int(fd), line) })
	}
}
