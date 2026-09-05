// SPDX-License-Identifier: AGPL-3.0-only

// Package filewatch watches configuration files, including atomic replacements
// and files whose parent directories do not exist yet.
package filewatch

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

type Watcher struct {
	// Changes signals that the caller should read the file. It includes an
	// initial notification to cover changes between the caller's first read
	// and starting the watch. Unread notifications are coalesced.
	Changes <-chan struct{}
	// Errors reports watch failures. Only one unread error is retained;
	// every failure also schedules a Changes notification to resync the file.
	Errors <-chan error

	watcher *fsnotify.Watcher
	done    chan struct{}
}

// New watches filename without creating files or directories. Changes are
// emitted after a quiet period of debounce, with no periodic polling.
func New(filename string, debounce time.Duration) (*Watcher, error) {
	filename, err := filepath.Abs(filename)
	if err != nil {
		return nil, err
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	if err := watchDirectories(watcher, filename); err != nil {
		watcher.Close()
		return nil, err
	}
	changes := make(chan struct{}, 1)
	failures := make(chan error, 1)
	w := &Watcher{Changes: changes, Errors: failures, watcher: watcher, done: make(chan struct{})}
	go w.run(filename, debounce, changes, failures)
	return w, nil
}

// Close releases the watch and waits for both notification channels to close.
func (w *Watcher) Close() error {
	err := w.watcher.Close()
	<-w.done
	return err
}

func (w *Watcher) run(filename string, debounce time.Duration, changes chan<- struct{}, failures chan<- error) {
	defer close(w.done)
	defer close(changes)
	defer close(failures)
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		var err error
		select {
		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			if !event.Has(fsnotify.Create|fsnotify.Write|fsnotify.Remove|fsnotify.Rename) ||
				(event.Name != filename && !strings.HasPrefix(filename, event.Name+string(filepath.Separator))) {
				continue
			}
			if event.Name != filename && event.Has(fsnotify.Create|fsnotify.Remove|fsnotify.Rename) {
				err = watchDirectories(w.watcher, filename)
			}
		case failure, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			// Overflow may lose directory-creation events as well as file writes.
			err = errors.Join(failure, watchDirectories(w.watcher, filename))
		case <-timer.C:
			select {
			case changes <- struct{}{}:
			default:
			}
			continue
		}
		if err != nil {
			select {
			case failures <- fmt.Errorf("watch %s: %w", filename, err):
			default:
			}
		}
		timer.Reset(debounce)
	}
}

// Watch every ancestor: moving an ancestor does not notify its descendants.
func watchDirectories(watcher *fsnotify.Watcher, filename string) error {
	var directories []string
	for directory := filepath.Dir(filename); ; directory = filepath.Dir(directory) {
		directories = append(directories, directory)
		if filepath.Dir(directory) == directory {
			break
		}
	}
	// A path may now name a new inode. Remove old bindings before adding it
	// again, retaining the root watch throughout the rebuild.
	for _, previous := range watcher.WatchList() {
		if previous != directories[len(directories)-1] {
			_ = watcher.Remove(previous)
		}
	}
	// Register parents first so a move during registration is also observed.
	for _, directory := range slices.Backward(directories) {
		if err := watcher.Add(directory); err != nil {
			if os.IsNotExist(err) {
				return nil // Its watched parent will report creation.
			}
			return err
		}
	}
	return nil
}
