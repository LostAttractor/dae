// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/internal/apiserver"
)

// preparedPlane owns a candidate and any newly opened API listener until
// publication. The currently serving listener is borrowed and survives rejection.
type preparedPlane struct {
	plane       *control.ControlPlane
	api         *apiserver.Server
	previousAPI *apiserver.Server
}

func (p *preparedPlane) closeAPI() {
	if p.api != p.previousAPI {
		p.api.Close()
	}
}

func (p *preparedPlane) discard() error {
	p.closeAPI()
	return p.plane.Close()
}

func (a *application) preparePlane(ctx context.Context, conf *config.Config, inputs *controlInputs, load func(*http.Client) (control.PreparedMITM, error)) (*preparedPlane, error) {
	plane, err := newControlPlane(ctx, a.datapath, conf, inputs, a.settings, load)
	if err != nil {
		return nil, fmt.Errorf("prepare control plane: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, plane.Close())
	}
	api, err := prepareAPIServer(a.managementAPI, conf.Global.APIPort)
	if err != nil {
		return nil, errors.Join(err, plane.Close())
	}
	return &preparedPlane{plane: plane, api: api, previousAPI: a.managementAPI}, nil
}

// publishPlane adopts both resources only after successful routing publication.
// Rejection leaves the old generation usable. Partial activation is terminal:
// Runtime retains the resources needed to finish shutting down that generation.
func (a *application) publishPlane(candidate *preparedPlane, abort bool) error {
	if err := a.datapath.Publish(candidate.plane, abort); err != nil {
		candidate.closeAPI()
		if errors.Is(err, control.ErrPublicationRejected) {
			return errors.Join(err, candidate.plane.Close())
		}
		return &activationError{err}
	}
	a.plane = candidate.plane
	if a.managementAPI != candidate.api {
		a.managementAPI.Close()
	}
	a.managementAPI = candidate.api
	return nil
}
