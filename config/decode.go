/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"reflect"
	"strconv"
	"strings"
	"time"
)

func FuzzyDecode(to any, val string) bool {
	v := reflect.Indirect(reflect.ValueOf(to))
	if !v.IsValid() || !v.CanSet() {
		return false
	}
	if v.Type() == reflect.TypeFor[time.Duration]() {
		duration, err := time.ParseDuration(val)
		if err != nil {
			return false
		}
		v.SetInt(int64(duration))
		return true
	}
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		i, err := strconv.ParseInt(val, 0, v.Type().Bits())
		if err != nil {
			return false
		}
		v.SetInt(i)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		i, err := strconv.ParseUint(val, 0, v.Type().Bits())
		if err != nil {
			return false
		}
		v.SetUint(i)
	case reflect.Bool:
		switch strings.ToLower(val) {
		case "true", "t", "1", "y", "yes", "on":
			v.SetBool(true)
		case "false", "f", "0", "n", "no", "off":
			v.SetBool(false)
		default:
			return false
		}
	case reflect.String:
		v.SetString(val)
	case reflect.Slice:
		switch v.Interface().(type) {
		case []string:
			v.Set(reflect.ValueOf(strings.Split(val, ",")))
		case []time.Duration:
			var durations []time.Duration
			duration, err := time.ParseDuration(val)
			if err != nil {
				return false
			}
			durations = append(durations, duration)
			v.Set(reflect.ValueOf(durations))
		default:
			return false
		}
	default:
		return false
	}
	return true
}
