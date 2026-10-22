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
	"time"

	"github.com/daeuniverse/dae/plugins/surge/internal/processgroup"
)

//go:embed worker.js
var workerSource string

type worker struct {
	*processgroup.Process
	maxFrame  uint32
	stderr    workerLog
	idleSince time.Time
	retiring  bool // Protected by the pool lock; still occupies worker capacity.
	memory    memorySample
}

// Read only after Cmd.Wait has joined os/exec's copy goroutine.
type workerLog struct{ data []byte }

func (l *workerLog) Write(data []byte) (int, error) {
	l.data = append(l.data, data[:min(len(data), 4096-len(l.data))]...)
	return len(data), nil
}

// Called with the pool lock held; the group is created with the first worker.
func (p *Pool) startWorker() (*worker, error) {
	if p.group == nil {
		group, err := processgroup.NewPool("nodejs", p.poolMemory)
		p.group = group
		if err != nil {
			if group != nil {
				// A partially created group is retained only for final cleanup.
				p.groupErr = err
			}
			return nil, err
		}
	}
	limit := min(p.memoryLimit*6+65536, 256<<20)
	cmd := exec.Command(p.path, "--permission", "--no-addons", "--max-old-space-size="+strconv.FormatInt(p.memoryLimit>>20, 10), "-e", workerSource, strconv.FormatInt(limit, 10))
	cmd.Env = []string{"LANG=C.UTF-8"}
	if zone, ok := os.LookupEnv("TZ"); ok {
		cmd.Env = append(cmd.Env, "TZ="+zone)
	}
	w := &worker{maxFrame: uint32(limit)}
	cmd.Stderr = &w.stderr
	process, err := p.group.Start(cmd, p.workerMemory)
	if err != nil {
		return nil, err
	}
	w.Process = process
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
	if _, err := w.Input.Write(header[:]); err != nil {
		return err
	}
	_, err = w.Input.Write(data)
	return err
}

func (w *worker) read() (response, error) {
	var header [4]byte
	if _, err := io.ReadFull(w.Output, header[:]); err != nil {
		return response{}, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > w.maxFrame {
		return response{}, errors.New("nodejs: invalid message length")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(w.Output, data); err != nil {
		return response{}, err
	}
	var result response
	err := json.Unmarshal(data, &result)
	return result, err
}
