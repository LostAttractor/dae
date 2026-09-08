/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

func ReportMemory(tag string) {
	if !log.IsLevelEnabled(log.DebugLevel) {
		return
	}
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(os.Getpid()), "status"))
	if err != nil {
		log.WithError(err).Debug("Could not read process memory usage")
		return
	}
	str := strings.TrimSpace(string(b))
	_, after, _ := strings.Cut(str, "VmHWM:")
	usage, _, _ := strings.Cut(after, "\n")
	log.WithFields(log.Fields{"phase": tag, "peak_rss": strings.TrimSpace(usage)}).Debug("Process memory usage")
}
