/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"testing"
)

func TestExportOutline(t *testing.T) {
	outline := ExportOutline("test")
	var group *OutlineElem
	for _, section := range outline.Structure {
		if section.Mapping == "group" {
			group = section
			break
		}
	}
	if group == nil {
		t.Fatal("group outline is missing")
	}
	for _, field := range group.Structure {
		if field.Name == "Paths" && field.Mapping == "path" && field.Desc != "" {
			return
		}
	}
	t.Fatal("group path outline is missing")
}
