// SPDX-License-Identifier: AGPL-3.0-only

// Package testutil contains shared contract checks for host and plugin APIs.
package testutil

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

type Schema struct {
	Const      *int               `json:"const"`
	Ref        string             `json:"$ref"`
	Type       string             `json:"type"`
	Format     string             `json:"format"`
	Properties map[string]Schema  `json:"properties"`
	Required   requiredProperties `json:"required"`
	Items      *Schema            `json:"items"`
	Additional json.RawMessage    `json:"additionalProperties"`
	AnyOf      []Schema           `json:"anyOf"`
	MinItems   int                `json:"minItems"`
	MaxItems   int                `json:"maxItems"`
}

// An omitted required keyword is valid; an explicit null is not a string array.
type requiredProperties []string

func (r *requiredProperties) UnmarshalJSON(data []byte) error {
	var names []string
	if err := json.Unmarshal(data, &names); err != nil {
		return err
	}
	if names == nil {
		return fmt.Errorf("schema required must be an array of unique strings")
	}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if seen[name] {
			return fmt.Errorf("schema required repeats %q", name)
		}
		seen[name] = true
	}
	*r = names
	return nil
}

type Schemas map[string]Schema

func LoadSchemas(t *testing.T, paths ...string) Schemas {
	t.Helper()
	schemas := make(Schemas)
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var document struct {
			OpenAPI    string `json:"openapi"`
			Components struct {
				Schemas Schemas `json:"schemas"`
			} `json:"components"`
		}
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatal(err)
		}
		if document.OpenAPI != "3.1.0" {
			t.Fatal("unexpected OpenAPI version")
		}
		for name, schema := range document.Components.Schemas {
			schemas[name] = schema
		}
	}
	return schemas
}

func (schemas Schemas) Check(t *testing.T, types ...reflect.Type) {
	t.Helper()
	var check func(reflect.Type, Schema)
	check = func(typ reflect.Type, schema Schema) {
		t.Helper()
		if schema.Ref != "" {
			_, name, ok := strings.Cut(schema.Ref, "#/components/schemas/")
			if !ok {
				t.Fatalf("unexpected schema reference %s", schema.Ref)
			}
			schema, ok = schemas[name]
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
		case typ.Kind() == reflect.Map:
			want = "object"
			if typ.Key().Kind() != reflect.String {
				t.Fatal("non-string JSON map key")
			}
			var value Schema
			if err := json.Unmarshal(schema.Additional, &value); err != nil {
				t.Fatalf("%s: missing map value schema: %v", typ, err)
			}
			check(typ.Elem(), value)
		case typ.Kind() == reflect.Bool:
			want = "boolean"
		case typ.Kind() == reflect.Float64:
			want = "number"
		case typ.Kind() == reflect.Int || typ.Kind() == reflect.Int64 || typ.Kind() == reflect.Uint32 || typ.Kind() == reflect.Uint64:
			want = "integer"
		default:
			t.Fatalf("undocumented wire type %s", typ)
		}
		if schema.Type != want {
			t.Errorf("%s: JSON type=%q want %q", typ, schema.Type, want)
		}
	}
	for _, typ := range types {
		check(typ, schemas[typ.Name()])
	}
}
