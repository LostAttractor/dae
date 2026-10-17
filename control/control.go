/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

//go:generate go run -mod=mod github.com/cilium/ebpf/cmd/bpf2go -type routing_result -cc "$BPF_CLANG" "$BPF_STRIP_FLAG" -cflags "$BPF_CFLAGS" -target "$BPF_TARGET" bpf kern/tproxy.c -- -I../kern
//go:generate go run ../cmd/dae-bpf-pack bpf_bpf*.go
//go:generate go run -mod=mod github.com/cilium/ebpf/cmd/bpf2go -no-global-types -type routing_limits -type http_client_kind -type http_client_layout -type api_client_link_type -type handoff_constants -type outbound_index -type outbound_connectivity_state -type capture_flags -type route_result_bits -type match_flags -type MatchType -type MatchAction -type L4ProtoType -type IpVersionType -tags ignore -cc "$BPF_CLANG" "$BPF_STRIP_FLAG" -target "$BPF_TARGET" bpfabi kern/routing_abi.c
//go:generate go run ../cmd/dae-routing-abi -output ../internal/routingabi/abi_generated.go bpfabi_bpf*.go
