/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"path"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/network"
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func splitWanInterfaces(ifnames []string) (manual []string, auto bool) {
	for _, ifname := range common.Deduplicate(ifnames) {
		if ifname == "auto" {
			auto = true
			continue
		}
		manual = append(manual, ifname)
	}
	return manual, auto
}

func (c *ControlPlane) bindHostInterfaces() error {
	core := c.core
	core.ifmgr.SetResetCallback(core.resetHostTCXLinks)
	hostEnabled := len(c.lanInterface) > 0 || len(c.wanInterface) > 0 || c.autoWan
	if hostEnabled {
		core.ifmgr.SetChangeCallback(c.requestHostReconcile)
	}
	if len(c.lanInterface) > 0 {
		if c.autoConfigKernelParameter {
			if err := SetIpv4forward("1"); err != nil {
				return oops.Errorf("configure host forwarding: %w", err)
			}
			if err := setForwarding("all", consts.IpVersionStr_6, "1"); err != nil {
				return oops.Errorf("configure host forwarding: %w", err)
			}
		}
		for _, ifname := range c.lanInterface {
			if err := core.bindLan(ifname, c.autoConfigKernelParameter); err != nil {
				return err
			}
		}
	}
	wanEnabled := len(c.wanInterface) > 0 || c.autoWan
	retryHost := false
	if wanEnabled {
		if err := core.ifmgr.RegisterWithPatternSync("*", nil, nil, core.invalidateWanLink); err != nil {
			return oops.Errorf("register WAN link deletion handler: %w", err)
		}
		if err := core.setupSkPidMonitor(); err != nil {
			return oops.Wrapf(err, "setup WAN socket identity monitor")
		}
		for _, ifname := range c.wanInterface {
			if err := core.bindWan(ifname, c.prepareWanInterface); err != nil {
				return err
			}
		}
		retryHost = c.reconcileWan()
	}
	if hostEnabled {
		c.hostReconcileDone = make(chan struct{})
		go c.runHostReconciler()
		if retryHost {
			c.requestHostReconcile()
		}
	}
	return nil
}

func (c *ControlPlane) prepareWanInterface(ifname string) error {
	if len(c.lanInterface) == 0 || !c.autoConfigKernelParameter {
		return nil
	}
	// IPv6 forwarding suppresses accept_ra=1. Routers that also consume an
	// upstream RA need mode 2 instead.
	acceptRa := sysctl.Keyf("net.ipv6.conf.%v.accept_ra", ifname)
	return prepareWanAcceptRA(ifname, acceptRa.Get, func(value string) error {
		return acceptRa.Set(value, false)
	})
}

func prepareWanAcceptRA(ifname string, get func() (string, error), set func(string) error) error {
	name := fmt.Sprintf("net.ipv6.conf.%s.accept_ra", ifname)
	value, err := get()
	if err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	if value != "1" {
		return nil
	}
	if err := set("2"); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

func (c *ControlPlane) reconcileWan() bool {
	if c.ctx.Err() != nil {
		return false
	}
	var snapshot *network.HostNetworkSnapshot
	if c.autoWan {
		current := c.core.netmon.Snapshot()
		if current.Revision() != 0 {
			snapshot = &current
		}
	}
	return c.core.reconcileWan(snapshot, c.prepareWanInterface)
}

func reconcileLanLinks(links []netlink.Link, patterns []string, bind func(netlink.Link) error) (retry bool) {
	for _, link := range links {
		if link.Attrs().Name == hostLinkName {
			continue
		}
		for _, pattern := range patterns {
			matched, _ := path.Match(pattern, link.Attrs().Name)
			if !matched {
				continue
			}
			if err := bind(link); err != nil {
				log.Errorf("bind LAN interface %s: %v", link.Attrs().Name, err)
				retry = true
			}
			break
		}
	}
	return retry
}

func (c *ControlPlane) reconcileLan() bool {
	if c.ctx.Err() != nil || len(c.lanInterface) == 0 {
		return false
	}
	links, err := netlink.LinkList()
	if err != nil {
		log.Errorf("list LAN interfaces: %v", err)
		return true
	}
	return reconcileLanLinks(links, c.lanInterface, func(link netlink.Link) error {
		return c.core.prepareAndBindLanLink(link, c.autoConfigKernelParameter)
	})
}

func (c *ControlPlane) reconcileHostInterfaces() bool {
	retry := c.reconcileLan()
	return c.reconcileWan() || retry
}

func (c *ControlPlane) requestHostReconcile() {
	if c.ctx.Err() != nil {
		return
	}
	select {
	case c.hostReconcileCh <- struct{}{}:
	default:
	}
}

func (c *ControlPlane) runHostReconciler() {
	defer close(c.hostReconcileDone)
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	var retryCh <-chan time.Time
	reconcile := func() {
		if c.reconcileHostInterfaces() {
			if retryCh == nil {
				timer.Reset(5 * time.Second)
				retryCh = timer.C
			}
			return
		}
		if retryCh != nil {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			retryCh = nil
		}
	}
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.hostReconcileCh:
			reconcile()
		case <-retryCh:
			retryCh = nil
			reconcile()
		}
	}
}
