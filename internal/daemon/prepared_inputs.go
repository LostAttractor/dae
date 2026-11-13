// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"

	"github.com/daeuniverse/dae/common/fileio"
	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/internal/handoff"
	"golang.org/x/sys/unix"
)

// InitializationContext freezes only startup readers, never the lifetime context
// used by published services or subsequent reloads.
func (s *Startup) InitializationContext() context.Context {
	if s.inputs != nil {
		return resource.WithInputReplay(s.ctx, s.inputs)
	}
	return s.ctx
}

func readPreparedInputs(ctx context.Context, file *os.File) (*resource.Inputs, error) {
	size, err := handoff.SealedFileSize(file, resource.MaxInputArchiveBytes)
	if err != nil {
		return nil, err
	}
	return resource.DecodeInputs(fileio.NewContextReader(ctx, io.NewSectionReader(file, 0, size)))
}

// The target parses, routes and validates its own inputs, without a business
// Runtime, live plugins, workers, or reads of mutable runtime settings.
func prepareReplacementInputs(ctx context.Context, path string, request preflightRequest, definitions map[string]plugin.Definition) (*resource.Inputs, error) {
	ctx, recorded := resource.WithInputRecording(ctx)
	conf, _, err := config.LoadContext(ctx, path)
	if err != nil {
		return nil, err
	}
	if !slices.Equal(conf.Global.LanInterface, request.LAN) || !slices.Equal(conf.Global.WanInterface, request.WAN) {
		return nil, errors.New("interception interfaces changed; reload configuration before replacing the executable")
	}
	plugins, err := configurePlugins(conf, definitions)
	if err != nil {
		return nil, err
	}
	if err := plugins.Preflight(ctx); err != nil {
		return nil, err
	}
	if err := control.CheckKernelFeatures(ctx); err != nil {
		return nil, err
	}
	if err := control.CheckProductionBPF(ctx); err != nil {
		return nil, err
	}
	resolver, err := InstallDefaultResolver(conf.Global.SoMarkFromDae, conf.Global.DNSResolver)
	if err != nil {
		return nil, err
	}
	defer resolver.SetRoute(nil)
	certificates, err := prepareCertificates(conf, nil)
	if err != nil {
		return nil, err
	}
	dirs := []string{filepath.Dir(path)}
	inputs, err := loadControlInputs(ctx, conf, false, dirs, path, nil)
	if err != nil {
		return nil, err
	}
	plane, err := control.NewUserspaceControlPlane(ctx, control.UserspaceResources{
		ProcessIdentity:      &request.Identity,
		SelectorHints:        request.SelectorHints,
		SkipConnectivityWait: len(configuredPluginSpecs(conf)) == 0,
	}, inputs.rules, inputs.nodes, conf, nil, func(client *http.Client) (control.PreparedMITM, error) {
		return loadMITM(ctx, conf, certificates.Authority(), client, nil, plugins, nil, dirs, nil)
	})
	if err != nil {
		return nil, err
	}
	if err := plane.Close(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return recorded, nil
}

func validateEmptyInputFile(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil {
		return err
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != 0 || seals != 0 || flags&unix.O_ACCMODE != unix.O_RDWR {
		return errors.New("preflight input descriptor must be an empty writable sealable file")
	}
	return nil
}
