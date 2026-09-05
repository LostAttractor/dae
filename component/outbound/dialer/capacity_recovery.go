package dialer

import (
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	log "github.com/sirupsen/logrus"
)

// Capacity work shares the checker's operation gate and global slots, but its
// failure never invalidates the health proof of still-serving sibling slots.
func (c *connectivityChecker) finishCapacity(result checkResult, applied bool) {
	if c.d.session == nil {
		return
	}
	snapshot := c.d.session.Snapshot()
	if !applied || !snapshot.Accepting {
		c.capacityTimer.Stop()
		c.capacityRetryAt = time.Time{}
		if snapshot.State == netproxy.SessionClosed {
			c.stopRetries()
			c.d.setRecovery(RecoveryStopped, time.Time{}, "")
		} else {
			c.healthDue = true
		}
		return
	}
	if reason := recoveryBlockedReason(result.connectErr); reason != "" {
		c.capacityBlockReason = reason
		c.d.updateRecovery(RecoveryBlocked, time.Time{}, reason, "replenish")
		return
	}
	if result.connectErr == nil && !snapshot.RecoveryRequired {
		c.capacityInterval = 0
		c.d.setRecovery(RecoveryReady, time.Time{}, "")
		return
	}
	if result.connectErr != nil {
		log.WithField("node", c.d.Name).WithError(result.connectErr).Debug("Outbound capacity replenishment failed; existing capacity remains usable")
	}
	maximum := c.d.CheckIntervalMax
	if maximum <= 0 {
		maximum = time.Hour
	}
	if c.capacityInterval == 0 {
		c.capacityInterval = checkBackoffInitialInterval
	} else {
		c.capacityInterval = min(c.capacityInterval*2, maximum)
	}
	deadline := time.Now().Add(jitterRetryInterval(c.capacityInterval, maximum))
	c.capacityRetryAt = deadline
	c.d.updateRecovery(RecoveryBackoff, deadline, "capacity", "replenish")
	c.capacityTimer.Reset(time.Until(deadline))
}

func (c *connectivityChecker) restoreCapacityStatus() {
	if !c.d.RuntimeStatus().Healthy {
		return
	}
	if c.capacityBlockReason != "" {
		c.d.updateRecovery(RecoveryBlocked, time.Time{}, c.capacityBlockReason, "replenish")
	} else if !c.capacityRetryAt.IsZero() {
		c.d.updateRecovery(RecoveryBackoff, c.capacityRetryAt, "capacity", "replenish")
	}
}
