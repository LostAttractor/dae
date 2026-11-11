// SPDX-License-Identifier: AGPL-3.0-only

package handoff

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func rawState(t *testing.T, data string, size int64, seals int) *os.File {
	t.Helper()
	fd, err := unix.MemfdCreate("handoff-test", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "test-state")
	t.Cleanup(func() { file.Close() })
	if _, err := file.WriteString(data); err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(size); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestSealedState(t *testing.T) {
	want := struct {
		Protocol int    `json:"protocol"`
		Name     string `json:"name"`
	}{Protocol: Protocol, Name: "sealed state"}
	file, err := SealState(want)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("state is not CLOEXEC: %x, %v", flags, err)
	}
	if _, err := file.Seek(1000, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		var got struct {
			Protocol int    `json:"protocol"`
			Name     string `json:"name"`
		}
		if err := ReadState(file, &got); err != nil || got != want {
			t.Fatalf("state=%+v: %v", got, err)
		}
	}
	if offset, err := file.Seek(0, io.SeekCurrent); err != nil || offset != 1000 {
		t.Fatalf("ReadState changed shared offset to %d: %v", offset, err)
	}
	if _, err := file.WriteAt([]byte("x"), 0); !errors.Is(err, unix.EPERM) {
		t.Fatalf("sealed write: %v", err)
	}
	for _, size := range []int64{0, maxStateSize + 1} {
		if err := file.Truncate(size); !errors.Is(err, unix.EPERM) {
			t.Fatalf("sealed truncate to %d: %v", size, err)
		}
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_FUTURE_WRITE); !errors.Is(err, unix.EPERM) {
		t.Fatalf("seal set was not frozen: %v", err)
	}
}

func TestSealStateBounds(t *testing.T) {
	for _, length := range []int{maxStateSize - 2, maxStateSize - 1, 2 * maxStateSize} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			file, err := SealState(strings.Repeat("x", length))
			if length == maxStateSize-2 {
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				var got string
				if err := ReadState(file, &got); err != nil || len(got) != length {
					t.Fatalf("state length=%d: %v", len(got), err)
				}
			} else if err == nil || file != nil {
				t.Fatalf("oversize state accepted: %v", err)
			}
		})
	}
	if file, err := SealState(make(chan int)); err == nil || file != nil {
		t.Fatalf("unsupported JSON value accepted: %v", err)
	}
}

func TestReadStateRejectsInvalidInput(t *testing.T) {
	for _, missing := range []int{stateSeals, unix.F_SEAL_WRITE, unix.F_SEAL_GROW, unix.F_SEAL_SHRINK, unix.F_SEAL_SEAL} {
		t.Run(fmt.Sprintf("missing-seal-%d", missing), func(t *testing.T) {
			file := rawState(t, `{}`, 2, stateSeals&^missing)
			if err := ReadState(file, new(struct{})); err == nil {
				t.Fatal("unsealed state accepted")
			}
		})
	}
	for _, size := range []int64{0, maxStateSize + 1} {
		t.Run(fmt.Sprintf("size-%d", size), func(t *testing.T) {
			file := rawState(t, "", size, stateSeals)
			if err := ReadState(file, new(struct{})); err == nil {
				t.Fatal("invalid size accepted")
			}
		})
	}
	for _, data := range []string{`{"unknown":1}`, `{"name":"a","name":"b"}`, `{} {}`, `{`} {
		t.Run(data, func(t *testing.T) {
			file := rawState(t, data, int64(len(data)), stateSeals)
			if err := ReadState(file, new(struct {
				Name string `json:"name"`
			})); err == nil {
				t.Fatal("invalid JSON accepted")
			}
		})
	}
	if err := ReadState(nil, new(struct{})); err == nil {
		t.Fatal("nil state accepted")
	}
	file, err := os.CreateTemp(t.TempDir(), "regular")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := ReadState(file, new(struct{})); err == nil {
		t.Fatal("regular file accepted")
	}
	file.Close()
	if err := ReadState(file, new(struct{})); err == nil {
		t.Fatal("closed state accepted")
	}
}

func TestInheritedFile(t *testing.T) {
	for _, fd := range []int{-1, 0, 1, 2, int(^uint(0) >> 1)} {
		if file, err := InheritedFile(fd, "invalid"); err == nil || file != nil {
			t.Fatalf("descriptor %d accepted", fd)
		}
	}
	fds := make([]int, 2)
	if err := unix.Pipe(fds); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])
	file, err := InheritedFile(fds[0], "pipe")
	if err != nil {
		unix.Close(fds[0])
		t.Fatal(err)
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("inherited FD not protected: %x, %v", flags, err)
	}
	file.Close()
	if file, err := InheritedFile(fds[0], "closed"); err == nil || file != nil {
		t.Fatal("closed FD accepted")
	}
}

func TestExecRejectsInvalidDescriptors(t *testing.T) {
	executable, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	file, err := SealState(struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	closed, err := SealState(struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	for _, tc := range []struct {
		name       string
		executable *os.File
		args       []string
		files      []*os.File
	}{
		{name: "nil executable", args: []string{"fixture"}},
		{name: "closed executable", executable: closed, args: []string{"fixture"}},
		{name: "missing argv0", executable: executable},
		{name: "empty argv0", executable: executable, args: []string{""}},
		{name: "nil file", executable: executable, args: []string{"fixture"}, files: []*os.File{nil}},
		{name: "closed file", executable: executable, args: []string{"fixture"}, files: []*os.File{closed}},
		{name: "duplicate files", executable: executable, args: []string{"fixture"}, files: []*os.File{file, file}},
		{name: "executable in files", executable: executable, args: []string{"fixture"}, files: []*os.File{executable}},
		{name: "stdio", executable: executable, args: []string{"fixture"}, files: []*os.File{os.Stdin}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := Exec(tc.executable, tc.args, nil, tc.files); err == nil {
				t.Fatal("invalid exec accepted")
			}
		})
	}
}
