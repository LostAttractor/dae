/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package logger

import (
	"sort"

	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var fieldPriority = map[string]int{
	"time":           0,
	"level":          1,
	"msg":            2,
	"network":        3,
	"application":    4,
	"action":         5,
	"source":         6,
	"destination":    7,
	"destination_ip": 8,
	"interface":      9,
	"qname":          10,
	"qtype":          11,
}

func sortFields(keys []string) {
	sort.Slice(keys, func(i, j int) bool {
		left, leftPrioritized := fieldPriority[keys[i]]
		right, rightPrioritized := fieldPriority[keys[j]]
		if leftPrioritized != rightPrioritized {
			return leftPrioritized
		}
		if leftPrioritized && left != right {
			return left < right
		}
		return keys[i] < keys[j]
	})
}

func SetLogger(logLevel string, disableTimestamp bool, logFileOpt *lumberjack.Logger) {
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		level = log.InfoLevel
	}

	log.SetLevel(level)
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: disableTimestamp,
		DisableQuote:     true,
		FullTimestamp:    true,
		TimestampFormat:  "2006-01-02 15:04:05",
		SortingFunc:      sortFields,
	})
	if logFileOpt != nil {
		log.SetOutput(logFileOpt)
	}
}
