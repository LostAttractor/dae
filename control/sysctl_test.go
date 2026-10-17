package control

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

func TestSetHostSysctl(t *testing.T) {
	for _, initial := range []string{"1\n", "0\n"} {
		t.Run(strings.TrimSpace(initial), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sysctl")
			if err := os.WriteFile(path, []byte(initial), 0600); err != nil {
				t.Fatal(err)
			}
			previous, changed, err := setHostSysctl("net.ipv4.ip_forward", path, "1")
			wantChange := initial == "0\n"
			if err != nil || previous != strings.TrimSpace(initial) || changed != wantChange {
				t.Fatalf("set = %q, %v, %v; want previous value and changed=%v", previous, changed, err, wantChange)
			}
			data, err := os.ReadFile(path)
			want := initial
			if wantChange {
				want = "1"
			}
			// An unchanged value retains its newline, proving no rewrite occurred.
			if err != nil || string(data) != want {
				t.Fatalf("file = %q, %v; want %q", data, err, want)
			}
		})
	}
	t.Run("read error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing")
		_, changed, err := setHostSysctl("net.ipv6.conf.all.forwarding", path, "1")
		failure, ok := errors.AsType[*os.PathError](err)
		if changed || !errors.Is(err, os.ErrNotExist) || !ok || failure.Op != "read" || failure.Path != "net.ipv6.conf.all.forwarding" {
			t.Fatalf("read failure lost context: changed=%v err=%v", changed, err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("failed read created a sysctl file")
		}
	})
	t.Run("write error", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root can write a read-only fixture")
		}
		path := filepath.Join(t.TempDir(), "sysctl")
		if err := os.WriteFile(path, []byte("0\n"), 0400); err != nil {
			t.Fatal(err)
		}
		previous, changed, err := setHostSysctl("net.ipv6.conf.all.forwarding", path, "1")
		failure, ok := errors.AsType[*os.PathError](err)
		if previous != "0" || changed || !errors.Is(err, os.ErrPermission) || !ok || failure.Op != "write" || failure.Path != "net.ipv6.conf.all.forwarding" {
			t.Fatalf("write failure lost context: previous=%q changed=%v err=%v", previous, changed, err)
		}
	})
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
