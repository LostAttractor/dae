/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"strconv"
)

func parsePositivePID(raw string) (int, error) {
	pid, err := strconv.ParseInt(raw, 10, 32)
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("invalid pid %q", raw)
	}
	return int(pid), nil
}
