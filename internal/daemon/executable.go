// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"sync"
)

func executableDigest(file *os.File) ([sha256.Size]byte, error) {
	hash := sha256.New()
	if _, err := io.Copy(hash, io.NewSectionReader(file, 0, 1<<63-1)); err != nil {
		return [sha256.Size]byte{}, err
	}
	return [sha256.Size]byte(hash.Sum(nil)), nil
}

var runningExecutableDigest = sync.OnceValues(func() ([sha256.Size]byte, error) {
	file, err := os.Open("/proc/self/exe")
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer file.Close()
	return executableDigest(file)
})

func needsReplacement(file *os.File, force bool) (bool, error) {
	if file == nil {
		return false, nil
	}
	candidate, err := executableDigest(file)
	if err != nil {
		return false, fmt.Errorf("hash candidate executable: %w", err)
	}
	current, err := runningExecutableDigest()
	if err != nil {
		return false, fmt.Errorf("hash running executable: %w", err)
	}
	return force || candidate != current, nil
}
