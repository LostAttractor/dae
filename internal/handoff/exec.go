// SPDX-License-Identifier: AGPL-3.0-only

package handoff

import (
	"debug/elf"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/daeuniverse/dae/common/fileio"
	"golang.org/x/sys/unix"
)

const (
	maxStateSize = 64 << 10
	stateSeals   = unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
)

type stateWriter struct {
	file      *os.File
	remaining int
}

func (w *stateWriter) Write(data []byte) (int, error) {
	if len(data) > w.remaining {
		return 0, errors.New("handoff state exceeds 64 KiB")
	}
	n, err := w.file.Write(data)
	w.remaining -= n
	return n, err
}

// NewSealableFile creates a private, initially empty CLOEXEC transport. A child
// may fill and seal it through ExtraFiles without sending descriptors back.
func NewSealableFile(name string) (*os.File, error) {
	fd, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func SealFile(file *os.File) error {
	if file == nil {
		return errors.New("missing handoff descriptor")
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, stateSeals); err != nil {
		return fmt.Errorf("seal handoff file: %w", err)
	}
	return nil
}

// SealedFileSize validates transport bounds without decoding its payload.
func SealedFileSize(file *os.File, maxBytes int64) (int64, error) {
	if file == nil || maxBytes <= 0 {
		return 0, errors.New("missing handoff descriptor or invalid byte limit")
	}
	seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil {
		return 0, fmt.Errorf("get handoff file seals: %w", err)
	}
	if seals&stateSeals != stateSeals {
		return 0, errors.New("unsealed handoff file")
	}
	info, err := file.Stat()
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxBytes {
		return 0, errors.New("invalid handoff file size or type")
	}
	return info.Size(), nil
}

// SealState writes at most 64 KiB of JSON into an immutable, CLOEXEC memfd.
func SealState(value any) (_ *os.File, resultErr error) {
	file, err := NewSealableFile("dae-handoff")
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			file.Close()
		}
	}()
	if err := json.MarshalWrite(&stateWriter{file: file, remaining: maxStateSize}, value); err != nil {
		return nil, fmt.Errorf("encode handoff state: %w", err)
	}
	if err := SealFile(file); err != nil {
		return nil, err
	}
	return file, nil
}

// ReadState validates the transport, not the daemon's manifest or descriptor roles.
func ReadState(file *os.File, value any) error {
	size, err := SealedFileSize(file, maxStateSize)
	if err != nil {
		return err
	}
	data := make([]byte, int(size))
	if _, err := file.ReadAt(data, 0); err != nil {
		return fmt.Errorf("read handoff state: %w", err)
	}
	return json.Unmarshal(data, value, json.RejectUnknownMembers(true))
}

// InheritedFile takes ownership of an inherited FD and immediately restores CLOEXEC.
// The caller must separately validate its role; an environment variable is not authority.
func InheritedFile(fd int, name string) (*os.File, error) {
	if fd < 3 {
		return nil, fmt.Errorf("invalid %s descriptor %d", name, fd)
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil {
		return nil, fmt.Errorf("validate %s descriptor: %w", name, err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags|unix.FD_CLOEXEC); err != nil {
		return nil, fmt.Errorf("protect %s descriptor: %w", name, err)
	}
	return os.NewFile(uintptr(fd), name), nil
}

// OpenExecutable pins a regular executable and rejects interpreter scripts.
func OpenExecutable(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	ref := os.NewFile(uintptr(fd), path)
	defer ref.Close()
	info, err := fileio.StatRegular(ref)
	if err != nil {
		return nil, err
	}
	if info.Mode()&0111 == 0 {
		return nil, fmt.Errorf("%s is not executable", path)
	}
	file, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return nil, fmt.Errorf("open executable %q: %w", path, err)
	}
	var magic [len(elf.ELFMAG)]byte
	_, err = file.ReadAt(magic[:], 0)
	if err != nil && !errors.Is(err, io.EOF) {
		_ = file.Close()
		return nil, fmt.Errorf("read executable %q: %w", path, err)
	}
	if string(magic[:]) != elf.ELFMAG {
		_ = file.Close()
		return nil, fmt.Errorf("%s is not an ELF executable", path)
	}
	return file, nil
}

// Exec replaces this process using an already-open ELF and explicit argv/environment.
// All descriptors must be distinct and >= 3. Only files survive, besides stdio.
// The caller must quiesce descriptor users first; errors do not roll back CLOEXEC changes.
func Exec(executable *os.File, args []string, env []string, files []*os.File) error {
	defer func() {
		runtime.KeepAlive(executable)
		runtime.KeepAlive(files)
	}()
	if len(args) == 0 || args[0] == "" {
		return errors.New("missing exec argv0")
	}
	seen := make(map[uintptr]bool, len(files)+1)
	validate := func(file *os.File) error {
		if file == nil {
			return errors.New("nil exec descriptor")
		}
		fd := file.Fd()
		if fd < 3 || fd == ^uintptr(0) || seen[fd] {
			return fmt.Errorf("invalid or duplicate exec descriptor for %s", file.Name())
		}
		if _, err := unix.FcntlInt(fd, unix.F_GETFD, 0); err != nil {
			return fmt.Errorf("validate exec descriptor %s: %w", file.Name(), err)
		}
		seen[fd] = true
		return nil
	}
	if err := validate(executable); err != nil {
		return err
	}
	for _, file := range files {
		if err := validate(file); err != nil {
			return err
		}
	}
	if err := unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return fmt.Errorf("protect exec descriptors: %w", err)
	}
	for _, file := range files {
		if _, err := unix.FcntlInt(file.Fd(), unix.F_SETFD, 0); err != nil {
			return fmt.Errorf("inherit %s: %w", file.Name(), err)
		}
	}
	return fmt.Errorf("exec replacement: %w", unix.Exec(fmt.Sprintf("/proc/self/fd/%d", executable.Fd()), args, env))
}
