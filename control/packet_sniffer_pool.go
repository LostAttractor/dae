/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/sniffing"
)

const (
	PacketSnifferTtl = 3 * time.Second
)

type PacketSniffer struct {
	*sniffing.Sniffer
	deadlineTimer *time.Timer
	Mu            sync.Mutex
}

// PacketSnifferPool is a full-cone udp conn pool
type PacketSnifferPool struct {
	pool             sync.Map
	snifferKeyLocker common.KeyLocker[PacketSnifferKey]
}
type PacketSnifferOptions struct {
	Ttl time.Duration
}

type PacketSnifferKey struct {
	LAddr netip.AddrPort
	RAddr netip.AddrPort
}

var DefaultPacketSnifferSessionMgr = NewPacketSnifferPool()

func NewPacketSnifferPool() *PacketSnifferPool {
	return &PacketSnifferPool{}
}

func (p *PacketSnifferPool) Remove(key PacketSnifferKey, sniffer *PacketSniffer) (err error) {
	sniffer.Mu.Lock()
	defer sniffer.Mu.Unlock()
	return p.removeLocked(key, sniffer)
}

func (p *PacketSnifferPool) removeLocked(key PacketSnifferKey, sniffer *PacketSniffer) error {
	if p.pool.CompareAndDelete(key, sniffer) {
		if sniffer.deadlineTimer != nil {
			sniffer.deadlineTimer.Stop()
		}
		return sniffer.Close()
	}
	return nil
}

func (p *PacketSnifferPool) Get(key PacketSnifferKey) *PacketSniffer {
	_qs, ok := p.pool.Load(key)
	if !ok {
		return nil
	}
	return _qs.(*PacketSniffer)
}

// TODO: 工作原理
func (p *PacketSnifferPool) GetOrCreate(key PacketSnifferKey, createOption *PacketSnifferOptions) (qs *PacketSniffer, isNew bool) {
	_qs, ok := p.pool.Load(key)
begin:
	if !ok {
		l, _ := p.snifferKeyLocker.Lock(key)
		defer p.snifferKeyLocker.Unlock(key, l)

		_qs, ok = p.pool.Load(key)
		if ok {
			goto begin
		}
		if createOption == nil {
			createOption = &PacketSnifferOptions{}
		}
		if createOption.Ttl == 0 {
			createOption.Ttl = PacketSnifferTtl
		}

		created := &PacketSniffer{
			Sniffer:       sniffing.NewPacketSniffer(nil, createOption.Ttl),
			Mu:            sync.Mutex{},
			deadlineTimer: nil,
		}
		created.Mu.Lock()
		p.pool.Store(key, created)
		created.deadlineTimer = time.AfterFunc(createOption.Ttl, func() {
			_ = p.Remove(key, created)
		})
		created.Mu.Unlock()
		qs = created
		_qs = created
		isNew = true
	}
	return _qs.(*PacketSniffer), isNew
}
