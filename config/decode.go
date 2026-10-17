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
	switch v.Kind() {
	case reflect.Int:
		i, err := strconv.ParseInt(val, 0, strconv.IntSize)
		if err != nil {
			return false
		}
		v.SetInt(i)
	case reflect.Int8:
		i, err := strconv.ParseInt(val, 0, 8)
		if err != nil {
			return false
		}
		v.SetInt(i)
	case reflect.Int16:
		i, err := strconv.ParseInt(val, 0, 16)
		if err != nil {
			return false
		}
		v.SetInt(i)
	case reflect.Int32:
		i, err := strconv.ParseInt(val, 0, 32)
		if err != nil {
			return false
		}
		v.SetInt(i)
	case reflect.Int64:
		switch v.Interface().(type) {
		case time.Duration:
			duration, err := time.ParseDuration(val)
			if err != nil {
				return false
			}
			v.Set(reflect.ValueOf(duration))
		default:
			i, err := strconv.ParseInt(val, 0, 64)
			if err != nil {
				return false
			}
			v.SetInt(i)
		}
	case reflect.Uint:
		i, err := strconv.ParseUint(val, 0, strconv.IntSize)
		if err != nil {
			return false
		}
		v.SetUint(i)
	case reflect.Uint8:
		i, err := strconv.ParseUint(val, 0, 8)
		if err != nil {
			return false
		}
		v.SetUint(i)
	case reflect.Uint16:
		i, err := strconv.ParseUint(val, 0, 16)
		if err != nil {
			return false
		}
		v.SetUint(i)
	case reflect.Uint32:
		i, err := strconv.ParseUint(val, 0, 32)
		if err != nil {
			return false
		}
		v.SetUint(i)
	case reflect.Uint64:
		i, err := strconv.ParseUint(val, 0, 64)
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
