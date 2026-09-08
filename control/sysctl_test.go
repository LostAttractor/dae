package control

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

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
