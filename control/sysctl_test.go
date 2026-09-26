package control

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

func TestSetHostSysctlWith(t *testing.T) {
	t.Run("same value does not write", func(t *testing.T) {
		writes := 0
		err := setHostSysctlWith("net.ipv4.ip_forward", "1", func() ([]byte, error) {
			return []byte("1\n"), nil
		}, func([]byte) error {
			writes++
			return nil
		})
		if err != nil || writes != 0 {
			t.Fatalf("same-value set = %v, writes = %d; want nil, 0", err, writes)
		}
	})

	t.Run("different value writes once", func(t *testing.T) {
		var writes [][]byte
		err := setHostSysctlWith("net.ipv4.ip_forward", "1", func() ([]byte, error) {
			return []byte("0\n"), nil
		}, func(value []byte) error {
			writes = append(writes, bytes.Clone(value))
			return nil
		})
		if err != nil || len(writes) != 1 || string(writes[0]) != "1" {
			t.Fatalf("changed-value set = %v, writes = %q; want nil, [1]", err, writes)
		}
	})

	for _, tc := range []struct {
		name      string
		readError bool
	}{
		{name: "read error", readError: true},
		{name: "write error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sentinel := errors.New("permission denied")
			err := setHostSysctlWith("net.ipv6.conf.all.forwarding", "1", func() ([]byte, error) {
				if tc.readError {
					return nil, sentinel
				}
				return []byte("0"), nil
			}, func([]byte) error {
				return sentinel
			})
			if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "net.ipv6.conf.all.forwarding") {
				t.Fatalf("set error = %v; want wrapped error with exact sysctl name", err)
			}
		})
	}
}

func TestSysctlWatchLogsRepairOutcome(t *testing.T) {
	logger := log.StandardLogger()
	hooks, level := logger.ReplaceHooks(make(log.LevelHooks)), logger.GetLevel()
	hook := logtest.NewGlobal()
	logger.SetLevel(log.InfoLevel)
	t.Cleanup(func() {
		logger.ReplaceHooks(hooks)
		logger.SetLevel(level)
	})
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "read failure", true: "repaired"}[existing], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sysctl")
			if existing {
				if err := os.WriteFile(path, []byte("0\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			events := make(chan fsnotify.Event, 1)
			manager := &SysctlManager{
				watcher: &fsnotify.Watcher{Events: events}, expectations: map[string]string{path: "1"},
			}
			hook.Reset()
			events <- fsnotify.Event{Name: path, Op: fsnotify.Write}
			close(events)
			manager.startWatch()
			entries := hook.AllEntries()
			if len(entries) != 1 || entries[0].Data["path"] != path {
				t.Fatalf("want one contextual outcome, got %+v", entries)
			}
			data, err := os.ReadFile(path)
			if !existing {
				if !errors.Is(err, os.ErrNotExist) || entries[0].Level != log.WarnLevel {
					t.Fatalf("failed read triggered a write or misleading success log: data=%q error=%v log=%+v", data, err, entries[0])
				}
			} else if err != nil || string(data) != "1" || entries[0].Level != log.InfoLevel {
				t.Fatalf("repair result: data=%q error=%v log=%+v", data, err, entries[0])
			}
		})
	}
}
