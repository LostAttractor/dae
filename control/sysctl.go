/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
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

func setHostSysctl(name, path, value string) error {
	return setHostSysctlWith(name, value, func() ([]byte, error) {
		return os.ReadFile(path)
	}, func(value []byte) error {
		return os.WriteFile(path, value, 0644)
	})
}

func setHostSysctlWith(name, value string, read func() ([]byte, error), write func([]byte) error) error {
	current, err := read()
	if err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	if string(bytes.TrimSpace(current)) == value {
		return nil
	}
	if err := write([]byte(value)); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

func setForwarding(ifname string, ipversion consts.IpVersionStr, val string) error {
	name := fmt.Sprintf("net.ipv%v.conf.%v.forwarding", ipversion, ifname)
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/forwarding", ipversion, ifname)
	return setHostSysctl(name, path, val)
}

func SetIpv4forward(val string) error {
	return setHostSysctl("net.ipv4.ip_forward", "/proc/sys/net/ipv4/ip_forward", val)
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
	return setHostSysctl(name, path, val)
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
					raw, err := os.ReadFile(event.Name)
					if err != nil {
						log.WithField("path", event.Name).WithError(err).Warn("Failed to verify required sysctl value")
						continue
					}
					value := strings.TrimSpace(string(raw))
					if value != expected {
						if err := os.WriteFile(event.Name, []byte(expected), 0644); err != nil {
							log.WithFields(log.Fields{"path": event.Name, "value": value, "required": expected}).
								WithError(err).Error("Failed to restore required sysctl value")
						} else {
							log.WithFields(log.Fields{"path": event.Name, "previous": value, "value": expected}).
								Info("Restored required sysctl value")
						}
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
	return os.WriteFile(path, []byte(value), 0644)
}
