//go:build linux && surge_nodejs

// SPDX-License-Identifier: AGPL-3.0-only

package nodejs

import (
	_ "embed"
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"
)

//go:embed worker.js
var workerSource string

type worker struct {
	cmd       *exec.Cmd
	input     io.WriteCloser
	output    io.ReadCloser
	maxFrame  uint32
	close     func()
	stderr    workerLog
	idleSince time.Time
	memory    memorySample
}

// Read only after Cmd.Wait has joined os/exec's copy goroutine.
type workerLog struct{ data []byte }

func (l *workerLog) Write(data []byte) (int, error) {
	l.data = append(l.data, data[:min(len(data), 4096-len(l.data))]...)
	return len(data), nil
}

func startWorker(path string, memoryLimit int64) (*worker, error) {
	limit := min(memoryLimit*6+65536, 256<<20)
	cmd := exec.Command(path, "--permission", "--no-addons", "--max-old-space-size="+strconv.FormatInt(memoryLimit>>20, 10), "-e", workerSource, strconv.FormatInt(limit, 10))
	cmd.Env = []string{"LANG=C.UTF-8"}
	if zone, ok := os.LookupEnv("TZ"); ok {
		cmd.Env = append(cmd.Env, "TZ="+zone)
	}
	// The plugin is Linux-only. Avoid orphan workers if the daemon exits abruptly.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		_ = input.Close()
		return nil, err
	}
	w := &worker{cmd: cmd, input: input, output: output, maxFrame: uint32(limit)}
	cmd.Stderr = &w.stderr
	if err := cmd.Start(); err != nil {
		_ = input.Close()
		_ = output.Close()
		return nil, err
	}
	w.close = sync.OnceFunc(func() {
		_ = w.cmd.Process.Kill()
		_ = w.input.Close()
		_ = w.output.Close()
		_ = w.cmd.Wait()
	})
	return w, nil
}

type command struct {
	Op    string `json:"op"`
	Text  string `json:"text,omitempty"`
	ID    int    `json:"id,omitzero"`
	Value any    `json:"value"`
	Error string `json:"error,omitempty"`
}

type response struct {
	Kind  string   `json:"kind"`
	Args  []string `json:"args"`
	Error string   `json:"error"`
}

func (w *worker) write(value command) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if uint64(len(data)) > uint64(w.maxFrame) {
		return errors.New("nodejs: message exceeds protocol limit")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	if _, err := w.input.Write(header[:]); err != nil {
		return err
	}
	_, err = w.input.Write(data)
	return err
}

func (w *worker) read() (response, error) {
	var header [4]byte
	if _, err := io.ReadFull(w.output, header[:]); err != nil {
		return response{}, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > w.maxFrame {
		return response{}, errors.New("nodejs: invalid message length")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(w.output, data); err != nil {
		return response{}, err
	}
	var result response
	err := json.Unmarshal(data, &result)
	return result, err
}
