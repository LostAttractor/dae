package logger

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func TestSetLoggerRendersStableNonTTYFormat(t *testing.T) {
	standard := log.StandardLogger()
	oldLevel := standard.Level
	oldFormatter := standard.Formatter
	oldOutput := standard.Out
	defer func() {
		standard.SetLevel(oldLevel)
		standard.SetFormatter(oldFormatter)
		standard.SetOutput(oldOutput)
	}()

	standard.SetOutput(&bytes.Buffer{})
	SetLogger("info", false, nil)
	entry := &log.Entry{
		Logger: standard,
		Data: log.Fields{
			"action":      "forward",
			"application": "dns",
			"component":   "test",
			"destination": "10.0.0.1:53",
			"network":     "udp4",
			"source":      "10.0.0.2:1234",
		},
		Time:    time.Date(2026, time.August, 14, 1, 2, 3, 0, time.UTC),
		Level:   log.InfoLevel,
		Message: "route",
	}

	rendered, err := standard.Formatter.Format(entry)
	if err != nil {
		t.Fatal(err)
	}
	want := "time=2026-08-14 01:02:03 level=info msg=route network=udp4 application=dns action=forward source=10.0.0.2:1234 destination=10.0.0.1:53 component=test\n"
	if string(rendered) != want {
		t.Fatalf("rendered log = %q, want %q", rendered, want)
	}
	entry.Data["plugin_instance"] = "personal"
	for _, disableTimestamp := range []bool{false, true} {
		SetLogger("info", disableTimestamp, nil)
		rendered, err = standard.Formatter.Format(entry)
		if err != nil {
			t.Fatal(err)
		}
		timestamp := "time=2026-08-14 01:02:03 "
		wantInstance := "plugin_instance=personal " + strings.TrimPrefix(want, timestamp)
		if !disableTimestamp {
			wantInstance = timestamp + wantInstance
		}
		if string(rendered) != wantInstance {
			t.Fatalf("instance context must precede severity and message: %q, want %q", rendered, wantInstance)
		}
	}
}

func TestSetLoggerPreservesSpecialCharacters(t *testing.T) {
	standard := log.StandardLogger()
	oldLevel := standard.Level
	oldFormatter := standard.Formatter
	oldOutput := standard.Out
	defer func() {
		standard.SetLevel(oldLevel)
		standard.SetFormatter(oldFormatter)
		standard.SetOutput(oldOutput)
	}()

	standard.SetOutput(&bytes.Buffer{})
	SetLogger("info", true, nil)
	entry := &log.Entry{
		Logger: standard,
		Data: log.Fields{
			"detail": "field \"value\"\tindented",
			"error":  errors.New(`compile routing: routing block "main": compile routing block "application": predicate functions require arguments`),
		},
		Level:   log.InfoLevel,
		Message: "message \"value\"\tindented\nnext line",
	}

	rendered, err := standard.Formatter.Format(entry)
	if err != nil {
		t.Fatal(err)
	}
	want := "level=info msg=message \"value\"\tindented\nnext line detail=field \"value\"\tindented" +
		` error=compile routing: routing block "main": compile routing block "application": predicate functions require arguments` + "\n"
	if string(rendered) != want {
		t.Fatalf("rendered log = %q, want %q", rendered, want)
	}
}

func TestTextFormatterRemovesExternalTerminalControls(t *testing.T) {
	const payload = "remote\x1b]52;c;YWJj\a\r\u009b2J"
	for _, color := range []bool{false, true} {
		f := NewTextFormatter(true).(*textFormatter)
		f.base.ForceColors = color
		entry := &log.Entry{Logger: log.New(), Level: log.InfoLevel, Message: payload,
			Data: log.Fields{"module": payload, "error": errors.New(payload)}}
		got, err := f.Format(entry)
		if err != nil {
			t.Fatal(err)
		}
		// Only the formatter's own coloring may survive in TTY output.
		plain := strings.ReplaceAll(strings.ReplaceAll(string(got), "\x1b[36m", ""), "\x1b[0m", "")
		if strings.ContainsAny(plain, "\x1b\a\r\u009b") || strings.Count(plain, "remote") != 3 {
			t.Fatalf("unsafe or missing log text: %q", got)
		}
		if entry.Message != payload || entry.Data["module"] != payload {
			t.Fatal("text formatter mutated structured log data")
		}
	}
}

type logStringValue string

func (v logStringValue) String() string { return string(v) }

type logFormattedValue struct{}

func (logFormattedValue) String() string { return "unused String method" }
func (logFormattedValue) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "formatted \x1b[31mvalue\x1b[0m")
}

func TestTextFormatterFieldValues(t *testing.T) {
	for _, test := range []struct {
		name  string
		value any
		want  string
	}{
		{"string", "ordinary text", "ordinary text"},
		{"empty", "", ""},
		{"unicode", "中文🙂", "中文🙂"},
		{"controls", "re\x1b[31mmote\x1b[0m\r", "remote"},
		{"invalid UTF-8", "a\xffb", "a\ufffdb"},
		{"integer", uint32(1234), "1234"},
		{"boolean", true, "true"},
		{"nil", nil, "<nil>"},
		{"bytes", []byte("hi"), "[104 105]"},
		{"error", errors.New("bad\rvalue"), "badvalue"},
		{"stringer", logStringValue("re\x1b[31mmote\x1b[0m"), "remote"},
		{"formatter", logFormattedValue{}, "formatted value"},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, color := range []bool{false, true} {
				f := NewTextFormatter(true).(*textFormatter)
				f.base.ForceColors = color
				const key = "de\x1b[31mtail\x1b[0m\nname"
				entry := &log.Entry{Logger: log.New(), Level: log.InfoLevel, Message: "check",
					Data: log.Fields{key: test.value}}
				want := "level=info msg=check detail name=" + test.want + "\n"
				if color {
					want = "\x1b[36mINFO\x1b[0m check \x1b[36mdetail name\x1b[0m=" + test.want + "\n"
				}
				got, err := f.Format(entry)
				if err != nil || string(got) != want {
					t.Fatalf("color=%v: got %q, %v; want %q", color, got, err, want)
				}
				if len(entry.Data) != 1 || !reflect.DeepEqual(entry.Data[key], test.value) || entry.Message != "check" {
					t.Fatal("formatter changed the original typed fields or message")
				}
			}
		})
	}
}
