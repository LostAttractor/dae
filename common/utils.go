/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
)

func ARangeU32(n uint32) []uint32 {
	ret := make([]uint32, n)
	for i := range n {
		ret[i] = i
	}
	return ret
}

func Ipv6ByteSliceToUint32Array(_ip []byte) (ip [4]uint32) {
	for j := 0; j < 16; j += 4 {
		ip[j/4] = internal.NativeEndian.Uint32(_ip[j : j+4])
	}
	return ip
}

func Deduplicate(list []string) []string {
	if list == nil {
		return nil
	}
	res := make([]string, 0, len(list))
	m := make(map[string]struct{})
	for _, v := range list {
		if _, ok := m[v]; ok {
			continue
		}
		m[v] = struct{}{}
		res = append(res, v)
	}
	return res
}

func ParseMac(mac string) (addr [6]byte, err error) {
	fields := strings.SplitN(mac, ":", 6)
	if len(fields) != 6 {
		return addr, fmt.Errorf("invalid mac: %v", mac)
	}
	for i, field := range fields {
		v, err := hex.DecodeString(field)
		if err != nil {
			return addr, fmt.Errorf("parse mac %v: %w", mac, err)
		}
		if len(v) != 1 {
			return addr, fmt.Errorf("invalid mac: %v", mac)
		}
		addr[i] = v[0]
	}
	return addr, nil
}

func ParsePortRange(pr string) (portRange [2]uint16, err error) {
	fields := strings.SplitN(pr, "-", 2)
	for i, field := range fields {
		if field == "" {
			return portRange, fmt.Errorf("bad port range: %v", pr)
		}
		port, err := strconv.Atoi(field)
		if err != nil {
			return portRange, err
		}
		if port < 0 || port > 0xffff {
			return portRange, fmt.Errorf("port %v exceeds uint16 range", port)
		}
		portRange[i] = uint16(port)
	}
	if len(fields) == 1 {
		portRange[1] = portRange[0]
	}
	return portRange, nil
}

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

func EnsureFileInSubDir(filePath string, dir string) (err error) {
	fileDir := filepath.Dir(filePath)
	if len(dir) == 0 {
		return fmt.Errorf("bad dir: %v", dir)
	}
	rel, err := filepath.Rel(dir, fileDir)
	if err != nil {
		return err
	}
	if strings.HasPrefix(rel, "..") {
		return fmt.Errorf("file is out of scope: %v", rel)
	}
	return nil
}

func ConvergeAddrPort(addrPort netip.AddrPort) netip.AddrPort {
	if addrPort.Addr().Is4In6() {
		return netip.AddrPortFrom(netip.AddrFrom4(addrPort.Addr().As4()), addrPort.Port())
	}
	return addrPort
}

func NewGcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Htons converts the unsigned short integer hostshort from host byte order to network byte order.
func Htons(i uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], i)
	return internal.NativeEndian.Uint16(b[:])
}

const InternalSoMarkFromDae uint32 = 0x100

// EffectiveSoMarkFromDae returns the mark used for dae's own sockets. A
// reserved default lets policy-routing rules identify dae's own sockets when
// so_mark_from_dae is left at zero.
func EffectiveSoMarkFromDae(mark uint32) uint32 {
	if mark != 0 {
		return mark
	}
	return InternalSoMarkFromDae
}

// ResolveSoMarkFromDae also reports whether the default was selected because
// the option was omitted, so callers can warn without warning for explicit 0.
func ResolveSoMarkFromDae(mark uint32, explicitlyConfigured bool) (effective uint32, autoSelected bool) {
	if mark != 0 {
		return mark, false
	}
	return InternalSoMarkFromDae, !explicitlyConfigured
}

func ValidateSoMarkFromDae(mark uint32) error {
	if mark&consts.TproxyMark != 0 {
		return fmt.Errorf("so_mark_from_dae %#x contains reserved tproxy mark %#x", mark, consts.TproxyMark)
	}
	return nil
}

func IsValidHttpMethod(method string) bool {
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "COPY", "HEAD", "OPTIONS", "LINK", "UNLINK", "PURGE", "LOCK", "UNLOCK", "PROPFIND", "CONNECT", "TRACE":
		return true
	default:
		return false
	}
}
