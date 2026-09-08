// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/daeuniverse/dae/common/consts"
	log "github.com/sirupsen/logrus"
)

const SignalProgressFilePath = "/var/run/dae.progress"

// writeReloadProgress reports the current reload step through the signal
// progress file, so `dae reload` can display it to the user.
func writeReloadProgress(format string, args ...any) {
	writeReloadState(consts.ReloadProcessing, fmt.Sprintf(format, args...))
}

func writeReloadState(code byte, content string) {
	data := []byte{code}
	if content != "" {
		data = append(data, []byte("\n"+content)...)
	}
	if err := writeFileAtomic(SignalProgressFilePath, data, 0600); err != nil {
		log.Warnf("Failed to update reload progress: %v", err)
	}
}

// writeFileAtomic prevents readers from observing a partially-written
// progress record while the daemon and CLI communicate through a file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if err = tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
