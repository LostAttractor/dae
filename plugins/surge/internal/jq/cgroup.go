// SPDX-License-Identifier: AGPL-3.0-only

package jq

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/plugins/surge/internal/processgroup"
)

const (
	WorkerMemory = 128 << 20
	MaxWorkers   = 4
	PoolMemory   = WorkerMemory * MaxWorkers
)

// Run refuses an internal entry point that was not started inside a hard limit.
func Run(input io.Reader, output io.Writer) error {
	_, path, err := processgroup.Current()
	if err != nil {
		return err
	}
	memory, err := os.ReadFile(filepath.Join(path, "memory.max"))
	if err != nil {
		return err
	}
	limit, err := strconv.ParseInt(strings.TrimSpace(string(memory)), 10, 64)
	if err != nil || limit <= 0 || limit > WorkerMemory {
		return ErrUnavailable
	}
	swap, err := os.ReadFile(filepath.Join(path, "memory.swap.max"))
	if err != nil || strings.TrimSpace(string(swap)) != "0" {
		return ErrUnavailable
	}
	return Serve(input, output)
}
