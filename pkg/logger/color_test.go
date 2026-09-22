// SPDX-License-Identifier: AGPL-3.0-only

package logger

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func TestColoredMessageHasNoFixedPadding(t *testing.T) {
	for _, message := range []string{"", "route", strings.Repeat("x", 43), strings.Repeat("x", 44), strings.Repeat("x", 60), strings.Repeat("界", 30), "  preserve  spaces  ", "line one\nline two\n", "ANSI \x1b[36mnetwork\x1b[0m=inside"} {
		for _, timestamp := range []bool{false, true} {
			for _, fields := range []bool{false, true} {
				f := NewTextFormatter(!timestamp).(*textFormatter)
				f.base.ForceColors = true
				entry := &log.Entry{Logger: log.New(), Level: log.InfoLevel, Message: message, Time: time.Date(2026, 9, 12, 1, 2, 3, 0, time.UTC)}
				if fields {
					entry.Data = log.Fields{"network": "tcp4", "detail": "keep  two spaces"}
				}
				got, err := f.Format(entry)
				want := "\x1b[36mINFO\x1b[0m"
				if timestamp {
					want += "[2026-09-12 01:02:03]"
				}
				want += " " + strings.TrimSuffix(message, "\n")
				if fields {
					want += " \x1b[36mnetwork\x1b[0m=tcp4 \x1b[36mdetail\x1b[0m=keep  two spaces"
				}
				want += "\n"
				if err != nil || string(got) != want {
					t.Fatalf("message=%q timestamp=%v fields=%v: got=%q want=%q error=%v", message, timestamp, fields, got, want, err)
				}
				if entry.Message != message {
					t.Fatal("formatter mutated the message")
				}
			}
		}
	}
}

func TestColoredCallerAndReusedBuffer(t *testing.T) {
	f := NewTextFormatter(false).(*textFormatter)
	f.base.ForceColors = true
	l := log.New()
	l.SetReportCaller(true)
	buffer := bytes.NewBufferString("already buffered\n")
	entry := &log.Entry{Logger: l, Level: log.WarnLevel, Message: "check", Time: time.Date(2026, 9, 12, 1, 2, 3, 0, time.UTC), Buffer: buffer,
		Caller: &runtime.Frame{File: "source file.go", Line: 7, Function: "pkg.check"}, Data: log.Fields{"key": "value"}}
	got, err := f.Format(entry)
	want := "already buffered\n\x1b[33mWARN\x1b[0m[2026-09-12 01:02:03]source file.go:7 pkg.check() check \x1b[33mkey\x1b[0m=value\n"
	if err != nil || string(got) != want || buffer.String() != want {
		t.Fatalf("got=%q buffer=%q error=%v", got, buffer.String(), err)
	}
}
