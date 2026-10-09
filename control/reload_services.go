// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net"
	"reflect"
	"time"

	"github.com/daeuniverse/dae/component/mitm"
	log "github.com/sirupsen/logrus"
)

func (c *ControlPlane) MITMHost() *mitm.Host {
	c.mitmMu.RLock()
	defer c.mitmMu.RUnlock()
	return c.mitmHost
}

// PrepareMITMSuccessor retains both instances and accepted routing resources
// for suspend, without reopening external files.
func (c *ControlPlane) PrepareMITMSuccessor() (PreparedMITM, error) {
	host, err := c.MITMHost().PrepareSuccessor()
	return PreparedMITM{Host: host, plan: c.mitmPlan}, err
}

// CanReplaceMITM checks all routing contributions, including complete capture
// predicates and expanded external inputs. Equal plans need no kernel replacement.
func (c *ControlPlane) CanReplaceMITM(prepared PreparedMITM) bool {
	return reflect.DeepEqual(c.mitmPlan, prepared.plan)
}

// ReplaceMITM publishes a prepared host whose routing contribution is unchanged.
// Existing protocol work drains under the old host's existing lifecycle rules.
func (c *ControlPlane) ReplaceMITM(prepared PreparedMITM) error {
	c.core.lifecycleMu.Lock()
	defer c.core.lifecycleMu.Unlock()
	if c.closedDone.Load() {
		return net.ErrClosed
	}
	if !c.CanReplaceMITM(prepared) {
		return errors.New("plugin routing declarations require a routing replacement")
	}
	host := prepared.Host
	if host != nil {
		if err := host.Start(c.ctx); err != nil {
			return err
		}
	}
	c.mitmMu.Lock()
	old := c.mitmHost
	c.mitmHost = host
	c.mitmMu.Unlock()
	if old != nil {
		old.StopWorkers()
		c.retiredHosts.Go(func() {
			// Admitted setups can still be between scope selection and protocol
			// admission. Use the same bounded handoff as routing replacement.
			timer := time.NewTimer(handoffLifetime)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-c.tcpSetupCtx.Done():
			}
			if c.abortConnections.Load() {
				old.Abort()
			}
			if err := old.Close(); err != nil {
				log.WithError(err).Error("Retire plugin protocol host")
			}
		})
	}
	return nil
}

// SetAPIKey is called after both API transports have drained.
func (c *ControlPlane) SetAPIKey(key string) { c.apiKey = key }

func (c *ControlPlane) useDNSAddress(name string, proxy bool) bool {
	c.mitmMu.RLock()
	defer c.mitmMu.RUnlock()
	return c.mitmHost.UseDNSAddress(name, proxy)
}
