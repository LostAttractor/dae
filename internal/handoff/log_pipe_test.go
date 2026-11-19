// SPDX-License-Identifier: AGPL-3.0-only

package handoff

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

func TestLogPipeValidationAndDelivery(t *testing.T) {
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		t.Fatal(err)
	}
	reader := os.NewFile(uintptr(fds[0]), "log-reader")
	defer reader.Close()
	writer := os.NewFile(uintptr(fds[1]), "log-writer")
	defer writer.Close()
	if err := ValidateLogPipe(writer); err != nil {
		t.Fatal(err)
	}
	if err := ValidateLogPipe(reader); err == nil {
		t.Fatal("accepted a read-only log pipe")
	}
	path := filepath.Join(t.TempDir(), "named-pipe")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	named, err := os.OpenFile(path, unix.O_PATH, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer named.Close()
	if err := ValidateAnonymousPipe(named); err == nil {
		t.Fatal("accepted a named pipe")
	}
	if err := reader.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	WriteLog(writer, []byte("preparing"))
	got := make([]byte, len("preparing\n"))
	if _, err := io.ReadFull(reader, got); err != nil || string(got) != "preparing\n" {
		t.Fatalf("mirrored stage = %q, %v", got, err)
	}
	WriteLog(writer, bytes.Repeat([]byte("\U0001f642"), 1100))
	got = make([]byte, 4096)
	n, err := reader.Read(got)
	if err != nil || !utf8.Valid(got[:n]) || !bytes.HasSuffix(got[:n], []byte(" [log entry truncated]\n")) {
		t.Fatalf("long mirrored record: bytes=%d error=%v", n, err)
	}
	for {
		_, err := unix.Write(fds[1], got)
		if errors.Is(err, unix.EAGAIN) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	WriteLog(writer, []byte("full pipe cannot block"))
	_ = reader.Close()
	WriteLog(writer, []byte("client exited"))
}
