// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"time"

	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/config"
	log "github.com/sirupsen/logrus"
)

func (c *planeHTTP) MITMHost() *mitm.Host {
	c.mitmMu.RLock()
	defer c.mitmMu.RUnlock()
	return c.mitmHost
}

// PrepareMITMSuccessor retains both instances and accepted routing resources
// for suspend, without reopening external files.
func (c *planeHTTP) PrepareMITMSuccessor() (PreparedMITM, error) {
	host, err := c.MITMHost().PrepareSuccessor()
	return PreparedMITM{Host: host, plan: c.mitmPlan}, err
}

// CanReplaceMITM checks all routing contributions, including complete capture
// predicates and expanded external inputs. Equal plans need no kernel replacement.
func (c *planeHTTP) CanReplaceMITM(prepared PreparedMITM) bool {
	return reflect.DeepEqual(c.mitmPlan, prepared.plan)
}

// ReplaceMITM publishes a prepared host whose routing contribution is unchanged.
// Existing protocol work drains under the old host's existing lifecycle rules.
func (c *ControlPlane) ReplaceMITM(prepared PreparedMITM, plugins config.Plugins) (err error) {
	c.core.lifecycleMu.Lock()
	defer c.core.lifecycleMu.Unlock()
	if c.closedDone.Load() {
		return fmt.Errorf("%w: %w", ErrPublicationRejected, net.ErrClosed)
	}
	if !c.CanReplaceMITM(prepared) {
		return fmt.Errorf("%w: plugin routing declarations require a routing replacement", ErrPublicationRejected)
	}
	host := prepared.Host
	old := c.MITMHost()
	if !old.SameInstances(host) {
		if runtime := c.core.bpf.Runtime; runtime != nil {
			if err := runtime.waitForRetirement(c.ctx); err != nil {
				return fmt.Errorf("%w: %w", ErrPublicationRejected, err)
			}
		}
		c.retiredHosts.Wait()
		handoff := c.pauseMITM(&c.planeHTTP)
		defer func() { handoff.complete(err) }()
	}
	releaseWorkers, err := old.DrainFor(host, false)
	if err != nil {
		return err
	}
	defer releaseWorkers()
	if host != nil {
		if err := host.Start(c.ctx); err != nil {
			return err
		}
	}
	c.mitmMu.Lock()
	c.mitmHost = host
	c.pluginStatus.Plugins = pluginConfigurationStatus(plugins)
	c.mitmMu.Unlock()
	if old != nil && old.SameInstances(host) {
		old.StopWorkers()
		c.retiredHosts.Go(func() {
			stopAbort := context.AfterFunc(c.tcpSetupCtx, func() {
				if c.abortConnections.Load() {
					old.Abort()
				}
			})
			defer stopAbort()
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

func (c *planeHTTP) useDNSAddress(name string) bool {
	c.mitmMu.RLock()
	defer c.mitmMu.RUnlock()
	return c.mitmHost.UseDNSAddress(name)
}
