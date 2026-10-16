// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"fmt"
	"path/filepath"

	"github.com/daeuniverse/dae/common"
	localca "github.com/daeuniverse/dae/component/ca"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/internal/apiserver"
	log "github.com/sirupsen/logrus"
)

// certificates is an immutable daemon identity shared by API and interception.
// A candidate is published with its configuration; a failed reload retains the
// accepted identity. Reusing it also preserves leaf caches and TLS connections.
type certificates struct {
	authority *localca.Authority
}

func (c *certificates) Authority() *localca.Authority {
	if c == nil {
		return nil
	}
	return c.authority
}

func (c *certificates) Public() *apiserver.Certificates {
	if c == nil {
		return nil
	}
	return &apiserver.Certificates{Identity: c.authority.Identity(), Handler: c.authority.Handler()}
}

func prepareCertificates(conf *config.Config, current *certificates) (*certificates, error) {
	settings := conf.Certificate
	if (settings.CACert == "") != (settings.CAKey == "") {
		return nil, fmt.Errorf("certificate: ca_cert and ca_key must be configured together")
	}
	var authority *localca.Authority
	var err error
	if settings.CACert != "" {
		resolve := func(path string) string {
			if filepath.IsAbs(path) {
				return path
			}
			return filepath.Join(common.CacheDirectory(), path)
		}
		authority, err = localca.Load(resolve(settings.CACert), resolve(settings.CAKey))
	} else if conf.Global.APIPort != 0 || conf.MITM.Enabled {
		authority, err = localca.Ensure(filepath.Join(common.CacheDirectory(), localca.ManagedDirectory))
	} else {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	if current != nil && current.authority.Fingerprint() == authority.Fingerprint() {
		return current, nil
	}
	return &certificates{authority: authority}, nil
}

func (a *application) setCertificates(next *certificates) {
	if a.certificates != next && next != nil {
		log.WithField("fingerprint", next.authority.Fingerprint()).Info("Loaded local CA for API HTTPS and MITM")
	}
	a.certificates = next
}
