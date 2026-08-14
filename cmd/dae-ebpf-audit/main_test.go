/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package main

import (
	"testing"
	"unsafe"

	"github.com/cilium/ebpf/btf"
)

func TestDaeParamSize(t *testing.T) {
	if size := unsafe.Sizeof(daeParam{}); size != daeParamSize {
		t.Fatalf("daeParam size is %d, want %d", size, daeParamSize)
	}
}

func TestValidateDaeParamType(t *testing.T) {
	u32 := &btf.Int{Name: "__u32", Size: 4, Encoding: btf.Unsigned}
	u8 := &btf.Int{Name: "__u8", Size: 1, Encoding: btf.Unsigned}
	valid := &btf.Struct{
		Name: "dae_param",
		Size: daeParamSize,
		Members: []btf.Member{
			{Name: "control_plane_pid", Type: u32, Offset: 0},
			{Name: "dae0_ifindex", Type: u32, Offset: 32},
			{Name: "dae0peer_ifindex", Type: u32, Offset: 64},
			{Name: "dae0peer_mac", Type: &btf.Array{Type: u8, Nelems: 6}, Offset: 96},
			{Name: "has_bpf_get_current_task", Type: u8, Offset: 144},
			{Name: "padding", Type: u8, Offset: 152},
		},
	}
	if err := validateDaeParamType(valid); err != nil {
		t.Fatalf("valid dae_param rejected: %v", err)
	}

	invalid := btf.Copy(valid).(*btf.Struct)
	invalid.Members[1], invalid.Members[2] = invalid.Members[2], invalid.Members[1]
	if err := validateDaeParamType(invalid); err == nil {
		t.Fatal("dae_param with reordered members was accepted")
	}
}

func TestValidateDaeParamQualifiers(t *testing.T) {
	strct := &btf.Struct{Name: "dae_param", Size: daeParamSize}
	qualified := &btf.Volatile{Type: &btf.Const{Type: strct}}
	if err := validateDaeParamQualifiers(qualified); err != nil {
		t.Fatalf("volatile const dae_param rejected: %v", err)
	}
	if err := validateDaeParamQualifiers(&btf.Const{Type: strct}); err == nil {
		t.Fatal("non-volatile dae_param accepted")
	}
}
