/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package logger

import (
	"bytes"
	"cmp"
	"fmt"
	"slices"
	"unicode/utf8"

	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var fieldPriority = map[string]int{
	"time":            0,
	"plugin_instance": 1,
	"level":           2,
	"msg":             3,
	"network":         4,
	"application":     5,
	"action":          6,
	"source":          7,
	"destination":     8,
	"destination_ip":  9,
	"interface":       10,
	"qname":           11,
	"qtype":           12,
}

func sortFields(keys []string) {
	slices.SortFunc(keys, func(a, b string) int {
		left, leftPrioritized := fieldPriority[a]
		right, rightPrioritized := fieldPriority[b]
		if leftPrioritized != rightPrioritized {
			if leftPrioritized {
				return -1
			}
			return 1
		}
		if leftPrioritized && left != right {
			return cmp.Compare(left, right)
		}
		return cmp.Compare(a, b)
	})
}

// NewTextFormatter keeps command diagnostics and daemon logs in the same format.
func NewTextFormatter(disableTimestamp bool) log.Formatter {
	return &textFormatter{base: log.TextFormatter{
		DisableTimestamp: disableTimestamp,
		FullTimestamp:    true,
		TimestampFormat:  "2006-01-02 15:04:05",
		SortingFunc:      sortFields,
	}}
}

type textFormatter struct {
	base log.TextFormatter
}

func (f *textFormatter) Format(entry *log.Entry) ([]byte, error) {
	start := 0
	if entry.Buffer != nil {
		start = entry.Buffer.Len()
	}
	// logrus trims a newline from the message in color mode; keep that local to
	// formatting rather than mutating the caller's entry.
	local := *entry
	rendered, err := f.base.Format(&local)
	if err != nil || !bytes.HasPrefix(rendered[start:], []byte("\x1b[")) {
		return rendered, err
	}

	// logrus v1.9 formats colored messages with "%-44s ". It offers no switch
	// for this padding. Locate the message from the fixed header configured
	// above, never by searching/trimming user text (which may contain spaces,
	// ANSI escapes, or text identical to a field). Field quoting, ordering,
	// terminal detection and colors remain the responsibility of logrus.
	headerEnd := start + bytes.Index(rendered[start:], []byte("\x1b[0m")) + len("\x1b[0m")
	if !f.base.DisableTimestamp {
		headerEnd += len(local.Time.Format(f.base.TimestampFormat)) + 2 // [timestamp]
	}
	if local.HasCaller() {
		headerEnd += len(fmt.Sprintf("%s:%d %s()", local.Caller.File, local.Caller.Line, local.Caller.Function))
	}
	messageEnd := headerEnd + 1 + len(local.Message)
	// Each field already supplies its own leading space. Remove logrus's extra
	// separator too, including when there are no fields or the message is long.
	padding := max(0, 44-utf8.RuneCountInString(local.Message)) + 1
	copy(rendered[messageEnd:], rendered[messageEnd+padding:])
	rendered = rendered[:len(rendered)-padding]
	if entry.Buffer != nil {
		entry.Buffer.Truncate(len(rendered))
	}
	return rendered, nil
}

func SetLogger(logLevel string, disableTimestamp bool, logFileOpt *lumberjack.Logger) {
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		level = log.InfoLevel
	}

	log.SetLevel(level)
	log.SetFormatter(NewTextFormatter(disableTimestamp))
	if logFileOpt != nil {
		log.SetOutput(logFileOpt)
	}
}
