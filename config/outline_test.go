/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"encoding/json"
	"testing"
)

func TestExportOutlineJSONCompatibility(t *testing.T) {
	const version = "test <version> & unicode 节点"
	want, err := json.MarshalIndent(ExportOutline(version), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if got := ExportOutlineJson(version); got != string(want) {
		t.Fatal("outline JSON changed field omission, escaping or formatting")
	}
}

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

func TestExportOutlineTreatsRoutingAsOpaque(t *testing.T) {
	outline := ExportOutline("test")
	var routing *OutlineElem
	for _, section := range outline.Structure {
		if section.Mapping == "routing" {
			routing = section
			break
		}
	}
	if routing == nil {
		t.Fatal("routing outline is missing")
	}
	if routing.Type != "config.Routing" || len(routing.Structure) != 0 {
		t.Fatalf("routing outline must be an opaque ordered policy: %+v", routing)
	}
}
