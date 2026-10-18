//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-only

package geodata

import "os"

// Without synchronous file change notifications, use the buffered decoder.
type geodataWatcher struct{}

func newGeodataWatcher() (*geodataWatcher, error) { return nil, os.ErrInvalid }
func (*geodataWatcher) add(*os.File) (int, error) { return 0, os.ErrInvalid }
func (*geodataWatcher) remove(int)                {}
func (*geodataWatcher) close()                    {}
func (*geodataWatcher) changes() (map[int]bool, bool, error) {
	return nil, false, os.ErrInvalid
}
