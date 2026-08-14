package logger

import (
	"bytes"
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
		Logger:  standard,
		Data:    log.Fields{"component": "test"},
		Time:    time.Date(2026, time.August, 14, 1, 2, 3, 0, time.UTC),
		Level:   log.InfoLevel,
		Message: "hello world",
	}

	rendered, err := standard.Formatter.Format(entry)
	if err != nil {
		t.Fatal(err)
	}
	want := "time=\"2026-08-14 01:02:03\" level=info msg=\"hello world\" component=test\n"
	if string(rendered) != want {
		t.Fatalf("rendered log = %q, want %q", rendered, want)
	}
}
