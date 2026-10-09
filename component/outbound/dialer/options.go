/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/config"
	D "github.com/daeuniverse/outbound/dialer"
)

type GlobalOption struct {
	D.ExtraOption
	SoMarkFromDae     uint32
	Mptcp             bool
	DNSResolver       string
	CheckDnsOptionRaw CheckDnsOptionRaw
	CheckInterval     time.Duration
	CheckIntervalMax  time.Duration
	CheckTolerance    time.Duration
}

func NewGlobalOption(global *config.Global) *GlobalOption {
	return &GlobalOption{
		SoMarkFromDae:       common.EffectiveSoMarkFromDae(global.SoMarkFromDae),
		Mptcp:               global.Mptcp,
		DNSResolver:         global.DNSResolver,
		AllowInsecure:       global.AllowInsecure,
		TlsImplementation:   global.TlsImplementation,
		UtlsImitate:         global.UtlsImitate,
		BandwidthMaxTx:      global.BandwidthMaxTx,
		BandwidthMaxRx:      global.BandwidthMaxRx,
		TlsFragment:         global.TlsFragment,
		TlsFragmentLength:   global.TlsFragmentLength,
		TlsFragmentInterval: global.TlsFragmentInterval,
		UDPHopInterval:      global.UDPHopInterval,
		CheckDnsOptionRaw:   CheckDnsOptionRaw{Raw: global.UdpCheckDns},
		CheckInterval:       global.CheckInterval,
		CheckIntervalMax:    global.CheckIntervalMax,
		CheckTolerance:      global.CheckTolerance,
	}
}
