// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

type documentedSchema struct {
	Const      *int                        `json:"const"`
	Ref        string                      `json:"$ref"`
	Type       string                      `json:"type"`
	Format     string                      `json:"format"`
	Properties map[string]documentedSchema `json:"properties"`
	Required   []string                    `json:"required"`
	Items      *documentedSchema           `json:"items"`
	AnyOf      []documentedSchema          `json:"anyOf"`
	MinItems   int                         `json:"minItems"`
	MaxItems   int                         `json:"maxItems"`
}

// Keep the readable, directly editable OpenAPI document aligned with the Go
// contract without maintaining a second API router in a documentation generator.
func TestOpenAPIMatchesWireTypes(t *testing.T) {
	data, err := os.ReadFile("../docs/api/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		OpenAPI    string `json:"openapi"`
		Components struct {
			Schemas map[string]documentedSchema `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if document.OpenAPI != "3.1.0" {
		t.Fatal("unexpected OpenAPI version")
	}
	version := document.Components.Schemas["StatusSnapshot"].Properties["schema"].Const
	if version == nil || *version != StatusSchemaVersion {
		t.Fatal("documented status schema version does not match the wire contract")
	}
	var check func(reflect.Type, documentedSchema)
	check = func(typ reflect.Type, schema documentedSchema) {
		t.Helper()
		if schema.Ref != "" {
			name, ok := strings.CutPrefix(schema.Ref, "#/components/schemas/")
			if !ok {
				t.Fatalf("unexpected schema reference %s", schema.Ref)
			}
			schema, ok = document.Components.Schemas[name]
			if !ok {
				t.Fatalf("missing schema %s", name)
			}
		}
		if typ.Kind() == reflect.Pointer {
			for _, alternative := range schema.AnyOf {
				if alternative.Type != "null" {
					schema = alternative
					break
				}
			}
			check(typ.Elem(), schema)
			return
		}
		want := ""
		switch {
		case typ == reflect.TypeFor[json.RawMessage]():
			if schema.Type != "" {
				t.Errorf("plugin reports must allow arbitrary JSON, got %q", schema.Type)
			}
			return
		case typ == reflect.TypeFor[time.Time]():
			want = "string"
			if schema.Format != "date-time" {
				t.Error("timestamp format missing")
			}
		case typ == reflect.TypeFor[time.Duration]():
			want = "integer"
		case typ.Kind() == reflect.Struct:
			want = "object"
			fields := map[string]reflect.StructField{}
			var collect func(reflect.Type)
			collect = func(typ reflect.Type) {
				for f := range typ.Fields() {
					if f.Tag.Get("json") == "-" {
						continue
					}
					if f.Anonymous {
						collect(f.Type)
					} else {
						name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
						fields[name] = f
					}
				}
			}
			collect(typ)
			if len(fields) != len(schema.Properties) {
				t.Errorf("%s: fields=%d documented=%d", typ, len(fields), len(schema.Properties))
			}
			for name, field := range fields {
				property, ok := schema.Properties[name]
				if !ok {
					t.Errorf("%s.%s is undocumented", typ, name)
					continue
				}
				required := !strings.Contains(field.Tag.Get("json"), ",omitempty") && !strings.Contains(field.Tag.Get("json"), ",omitzero")
				if slices.Contains(schema.Required, name) != required {
					t.Errorf("%s.%s: required/optional mismatch", typ, name)
				}
				check(field.Type, property)
			}
		case typ.Kind() == reflect.Array || typ.Kind() == reflect.Slice:
			want = "array"
			if schema.Items == nil {
				t.Fatalf("%s has no documented item type", typ)
			}
			if typ.Kind() == reflect.Array && (schema.MinItems != typ.Len() || schema.MaxItems != typ.Len()) {
				t.Errorf("%s: array size mismatch", typ)
			}
			check(typ.Elem(), *schema.Items)
		case typ.Kind() == reflect.String:
			want = "string"
		case typ.Kind() == reflect.Bool:
			want = "boolean"
		case typ.Kind() == reflect.Float64:
			want = "number"
		case typ.Kind() == reflect.Int || typ.Kind() == reflect.Int64 || typ.Kind() == reflect.Uint64:
			want = "integer"
		default:
			t.Fatalf("undocumented wire type %s", typ)
		}
		if schema.Type != want {
			t.Errorf("%s: JSON type=%q want %q", typ, schema.Type, want)
		}
	}
	for _, typ := range []reflect.Type{reflect.TypeFor[StatusSnapshot](), reflect.TypeFor[SurgeStatus](), reflect.TypeFor[SelectorsResponse](), reflect.TypeFor[DeviceState](), reflect.TypeFor[Certificate](), reflect.TypeFor[SelectNodeRequest](), reflect.TypeFor[SetMITMRequest]()} {
		check(typ, document.Components.Schemas[typ.Name()])
	}
}
