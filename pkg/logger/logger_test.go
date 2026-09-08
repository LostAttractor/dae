package logger

import (
	"bytes"
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
	want := "time=\"2026-08-14 01:02:03\" level=info msg=route network=udp4 application=dns action=forward source=\"10.0.0.2:1234\" destination=\"10.0.0.1:53\" component=test\n"
	if string(rendered) != want {
		t.Fatalf("rendered log = %q, want %q", rendered, want)
	}
	entry.Data["mitm_instance"] = "personal"
	for _, disableTimestamp := range []bool{false, true} {
		SetLogger("info", disableTimestamp, nil)
		rendered, err = standard.Formatter.Format(entry)
		if err != nil {
			t.Fatal(err)
		}
		timestamp := "time=\"2026-08-14 01:02:03\" "
		wantInstance := "mitm_instance=personal " + strings.TrimPrefix(want, timestamp)
		if !disableTimestamp {
			wantInstance = timestamp + wantInstance
		}
		if string(rendered) != wantInstance {
			t.Fatalf("instance context must precede severity and message: %q, want %q", rendered, wantInstance)
		}
	}
}

func TestSetLoggerEscapesSpecialCharacters(t *testing.T) {
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
		Logger:  standard,
		Data:    log.Fields{"detail": "field \"value\"\tindented"},
		Level:   log.InfoLevel,
		Message: "message \"value\"\tindented\nnext line",
	}

	rendered, err := standard.Formatter.Format(entry)
	if err != nil {
		t.Fatal(err)
	}
	want := `level=info msg="message \"value\"\tindented\nnext line" detail="field \"value\"\tindented"` + "\n"
	if string(rendered) != want {
		t.Fatalf("rendered log = %q, want %q", rendered, want)
	}
}
