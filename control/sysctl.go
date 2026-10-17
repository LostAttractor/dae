/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
)

func checkIpforward(ifname string, ipversion consts.IpVersionStr) error {
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/forwarding", ipversion, ifname)
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if bytes.Equal(bytes.TrimSpace(b), []byte("1")) {
		return nil
	}
	return fmt.Errorf("ipforward on %v is off: %v; see docs of dae for help", ifname, path)
}

func CheckIpforward(ifname string) error {
	if err := checkIpforward(ifname, consts.IpVersionStr_4); err != nil {
		return err
	}
	if err := checkIpforward(ifname, consts.IpVersionStr_6); err != nil {
		return err
	}
	return nil
}

// setHostSysctl writes only changed values. Callers own reporting; errors retain
// the operation and sysctl name as well as the underlying filesystem error.
func setHostSysctl(name, path, value string) (previous string, changed bool, err error) {
	current, err := os.ReadFile(path)
	if err != nil {
		return "", false, &os.PathError{Op: "read", Path: name, Err: err}
	}
	previous = strings.TrimSpace(string(current))
	if previous == value {
		return previous, false, nil
	}
	if err := os.WriteFile(path, []byte(value), 0644); err != nil {
		return previous, false, &os.PathError{Op: "write", Path: name, Err: err}
	}
	return previous, true, nil
}

func setForwarding(ifname string, ipversion consts.IpVersionStr, val string) error {
	name := fmt.Sprintf("net.ipv%v.conf.%v.forwarding", ipversion, ifname)
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/forwarding", ipversion, ifname)
	_, _, err := setHostSysctl(name, path, val)
	return err
}

func SetIpv4forward(val string) error {
	_, _, err := setHostSysctl("net.ipv4.ip_forward", "/proc/sys/net/ipv4/ip_forward", val)
	return err
}

func SetForwarding(ifname string, val string) error {
	if err := setForwarding(ifname, consts.IpVersionStr_4, val); err != nil {
		return err
	}
	return setForwarding(ifname, consts.IpVersionStr_6, val)
}

func checkSendRedirects(ifname string, ipversion consts.IpVersionStr) error {
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/send_redirects", ipversion, ifname)
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if bytes.Equal(bytes.TrimSpace(b), []byte("0")) {
		return nil
	}
	return fmt.Errorf("send_redirects on %v is on: %v; see docs of dae for help", ifname, path)
}

func CheckSendRedirects(ifname string) error {
	if err := checkSendRedirects(ifname, consts.IpVersionStr_4); err != nil {
		return err
	}
	return nil
}

func setSendRedirects(ifname string, ipversion consts.IpVersionStr, val string) error {
	name := fmt.Sprintf("net.ipv%v.conf.%v.send_redirects", ipversion, ifname)
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/send_redirects", ipversion, ifname)
	_, _, err := setHostSysctl(name, path, val)
	return err
}

func SetSendRedirects(ifname string, val string) error {
	return setSendRedirects(ifname, consts.IpVersionStr_4, val)
}

const SysctlPrefixPath = "/proc/sys/"

var sysctl *SysctlManager

type SysctlManager struct {
	mux          sync.Mutex
	watcher      *fsnotify.Watcher
	expectations map[string]string
}

// InitSysctlManager creates the global sysctl manager on first use. The
// manager is process-lifetime and shared by all control planes: re-creating
// it on reload would churn the fsnotify watcher, and a failed reload build
// would leave the running plane without its expectations.
func InitSysctlManager() (err error) {
	if sysctl != nil {
		return nil
	}
	sysctl, err = NewSysctlManager()
	return err
}

// CloseSysctlManager closes the global sysctl manager, if any, so that its
// fsnotify watcher and expectations are released.
func CloseSysctlManager() {
	if sysctl != nil {
		_ = sysctl.Close()
		sysctl = nil
	}
}

func NewSysctlManager() (*SysctlManager, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	manager := &SysctlManager{
		mux:          sync.Mutex{},
		watcher:      watcher,
		expectations: map[string]string{},
	}
	go manager.startWatch()
	return manager, nil
}

func (s *SysctlManager) startWatch() {
	for {
		select {
		case event, ok := <-s.watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) {
				log.WithField("path", event.Name).Trace("Observed sysctl write")
				s.mux.Lock()
				expected, ok := s.expectations[event.Name]
				s.mux.Unlock()
				if ok {
					previous, changed, err := setHostSysctl(event.Name, event.Name, expected)
					if err != nil {
						entry := log.WithFields(log.Fields{"path": event.Name, "required": expected}).WithError(err)
						if failure, ok := errors.AsType[*os.PathError](err); ok && failure.Op == "read" {
							entry.Warn("Failed to verify required sysctl value")
						} else {
							entry.Error("Failed to restore required sysctl value")
						}
						continue
					}
					if changed {
						log.WithFields(log.Fields{"path": event.Name, "previous": previous, "value": expected}).Info("Restored required sysctl value")
					}
				}
			}
		case err, ok := <-s.watcher.Errors:
			if !ok {
				return
			}
			log.WithError(err).Warn("Sysctl monitoring failed; required values may have changed")
		}
	}
}

func (s *SysctlManager) Close() error {
	if s == nil {
		return nil
	}
	// Closing the watcher also closes its Events/Errors channels, which makes
	// the startWatch goroutine exit.
	return s.watcher.Close()
}

type SysctlKey string

func (s *SysctlManager) Keyf(format string, a ...any) SysctlKey {
	return SysctlKey(SysctlPrefixPath + fmt.Sprintf(strings.ReplaceAll(format, ".", "/"), a...))
}

func (k SysctlKey) Get() (value string, err error) {
	return sysctl.get(string(k))
}

func (k SysctlKey) Set(value string, watch bool) (err error) {
	return sysctl.set(string(k), value, watch)
}

func (s *SysctlManager) get(path string) (value string, err error) {
	val, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(val)), nil
}

func (s *SysctlManager) set(path string, value string, watch bool) (err error) {
	if watch {
		s.mux.Lock()
		s.expectations[path] = value
		s.mux.Unlock()
		if err = s.watcher.Add(path); err != nil {
			return
		}
	}
	_, _, err = setHostSysctl(path, path, value)
	return err
}
