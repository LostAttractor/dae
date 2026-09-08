// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"github.com/daeuniverse/dae/api"
	log "github.com/sirupsen/logrus"
)

func logModuleStatus(status api.SurgeStatus, logger *log.Entry, instanceID string) {
	for _, module := range status.Modules {
		logger.WithFields(log.Fields{
			"mitm_instance": instanceID, "module": module.Name,
			"state": module.State, "scripts": module.Scripts,
		}).Info("Surge module loaded")
	}
}
