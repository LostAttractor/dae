/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package consts

import "fmt"

type SniffVerifyMode string

const (
	SniffVerifyMode_None   SniffVerifyMode = "none"
	SniffVerifyMode_Loose  SniffVerifyMode = "loose"
	SniffVerifyMode_Strict SniffVerifyMode = "strict"
)

type RerouteMode string

const (
	RerouteMode_None      RerouteMode = "none"
	RerouteMode_WhileNeed RerouteMode = "while_needed"
	RerouteMode_Force     RerouteMode = "force"
)

func VerifySniffVerifyMode(mode string) {
	switch mode {
	case "none", "loose", "strict":
	default:
		panic(fmt.Sprintf("unsupported sniff verify mode: %v", mode))
	}
}

func VerifyRerouteMode(mode string) {
	switch mode {
	case "none", "while_needed", "force":
	default:
		panic(fmt.Sprintf("unsupported reroute mode: %v", mode))
	}
}
