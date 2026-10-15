// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	surgeapi "github.com/daeuniverse/dae/plugins/surge/api"
	log "github.com/sirupsen/logrus"
)

func logModuleStatus(status surgeapi.SurgeStatus, logger *log.Entry, instanceID string) {
	for _, module := range status.Modules {
		logger.WithFields(log.Fields{
			"plugin_instance": instanceID, "module": module.Name,
			"state": module.State, "scripts": module.Scripts,
		}).Info("Surge module loaded")
	}
}
