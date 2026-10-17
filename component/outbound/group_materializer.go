// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	log "github.com/sirupsen/logrus"
)

// GroupMaterializer prepares one configuration's reachable targets. Its path
// budget and entry discovery cache are local to that preparation; Resources
// owns transport and group references shared across configurations.
// Calls are serialized by the configuration builder.
type GroupMaterializer struct {
	compiler         *GroupCompiler
	resources        *Resources
	global           *config.Global
	option           *dialer.GlobalOption
	entryDiscoveries EntryDiscoveries
	pathCount        int
}

func NewGroupMaterializer(compiler *GroupCompiler, resources *Resources, global *config.Global) *GroupMaterializer {
	compiler.set.UsePaths(&resources.Paths)
	return &GroupMaterializer{compiler: compiler, resources: resources, global: global, option: dialer.NewGlobalOption(global)}
}

// MaterializedGroup carries the caller's owned reference. Release must be
// called even if installing the group's routing projection fails.
type MaterializedGroup struct {
	Group    *DialerGroup
	Release  func() error
	Borrowed bool
}

func (m *GroupMaterializer) MaterializeGroup(ctx context.Context, target *ResolvedTarget) (*MaterializedGroup, error) {
	name := target.Name()
	var paths []*PathSpec
	if node := target.Node; node != nil {
		paths = []*PathSpec{NodePath(node)}
	}
	finalOption := m.option
	selectionPolicy := dialer.DialerSelectionPolicy{}
	if group := target.Group; group != nil {
		var err error
		paths, err = m.compiler.ExpandRoutable(group)
		if err != nil {
			return nil, fmt.Errorf("failed to expand group %v: %w", name, err)
		}
		if groupOption := parseGroupOverrideOption(*group, *m.global); groupOption != nil {
			finalOption = groupOption
			log.WithField("group", name).Debug("Using group connectivity check settings")
		}
		if group.Policy != nil {
			policy, err := dialer.NewDialerSelectionPolicyFromGroupParam(group)
			if err != nil {
				return nil, fmt.Errorf("failed to create group %v: %w", name, err)
			}
			selectionPolicy = *policy
		}
	}
	logicalPaths := len(paths)
	var err error
	paths, err = m.entryDiscoveries.ExpandIPVariants(ctx, paths, finalOption)
	if err != nil {
		return nil, fmt.Errorf("expand target %q address families: %w", name, err)
	}
	if logicalPaths == 1 && len(paths) > 1 && selectionPolicy.Policy == "" {
		selectionPolicy = dialer.DialerSelectionPolicy{
			Policy:   consts.DialerSelectionPolicy_MinMovingAverageLatencies,
			EmaAlpha: dialer.DefaultEmaAlpha,
		}
	}
	if len(paths) > MaxMaterializedPaths-m.pathCount {
		return nil, fmt.Errorf("materializing target %q would exceed the global proxy path limit %d", name, MaxMaterializedPaths)
	}

	pathKeys := make([]string, 0, len(paths))
	for _, path := range paths {
		pathKeys = append(pathKeys, GroupPathKey(path, finalOption))
	}
	key, err := json.Marshal(struct {
		Name               string
		Kind               TargetKind
		Policy             dialer.DialerSelectionPolicy
		Paths              []string
		Tolerance          int64
		CloseOnReselect    bool
		CloseOnRouteChange bool
	}{name, target.Kind, selectionPolicy, pathKeys, int64(finalOption.CheckTolerance), target.Group != nil && target.Group.ReselectBehavior == "close", m.global.RouteChangeBehavior == "close"}, json.Deterministic(true),
		json.WithMarshalers(json.MarshalFunc(func(value time.Duration) ([]byte, error) { return []byte(strconv.FormatInt(int64(value), 10)), nil })))
	if err != nil {
		return nil, err
	}
	created := false
	group, release, err := m.resources.Acquire(string(key), func() (*DialerGroup, error) {
		created = true
		dialers := make([]*dialer.Dialer, 0, len(paths))
		annotations := make([]*dialer.Annotation, 0, len(paths))
		pathOccurrences := make(map[string]int, len(paths))
		for _, path := range paths {
			d, buildErr := m.compiler.set.BuildPath(path, finalOption, candidateStatsScope(name, path, pathOccurrences))
			if buildErr != nil {
				pathBuildErr, isPathBuildErr := errors.AsType[*PathBuildError](buildErr)
				if isPathBuildErr && !pathBuildErr.Node.Required {
					log.WithFields(log.Fields{"node": pathBuildErr.Node.Property.Name, "target": name}).
						WithError(resource.RedactError(pathBuildErr.Err)).Warn("Could not build subscription path; skipping node")
					continue
				}
				for _, d := range dialers {
					_ = d.Close()
				}
				return nil, fmt.Errorf("failed to build target %v path: %w", name, buildErr)
			}
			dialers = append(dialers, d)
			annotations = append(annotations, path.Annotation)
		}

		if len(dialers) == 0 {
			return nil, fmt.Errorf("target %q has no usable paths", name)
		}
		group := NewDialerGroup(finalOption, name, GroupKindSelector, dialers, annotations, selectionPolicy).SetTargetMetadata(target.Kind)
		closeOnReselect := target.Group != nil && target.Group.ReselectBehavior == "close"
		group.SetConnectionPolicy(closeOnReselect, m.global.RouteChangeBehavior == "close")
		return group, nil
	})
	if err != nil {
		return nil, err
	}
	m.pathCount += len(group.Dialers)
	return &MaterializedGroup{Group: group, Release: release, Borrowed: !created}, nil
}

func candidateStatsScope(target string, path *PathSpec, occurrences map[string]int) string {
	identity := path.Identity()
	index := occurrences[identity]
	occurrences[identity] = index + 1
	return strconv.Itoa(len(target)) + ":" + target + ":" + strconv.Itoa(index)
}

func parseGroupOverrideOption(group config.Group, global config.Global) *dialer.GlobalOption {
	result := global
	changed := false
	if group.UdpCheckDns != nil {
		result.UdpCheckDns = group.UdpCheckDns
		changed = true
	}
	if group.CheckInterval != 0 {
		result.CheckInterval = group.CheckInterval
		changed = true
	}
	if group.CheckIntervalMax != 0 {
		result.CheckIntervalMax = group.CheckIntervalMax
		changed = true
	}
	if group.CheckTolerance != 0 || group.Present["check_tolerance"] {
		result.CheckTolerance = group.CheckTolerance
		changed = true
	}
	if changed {
		return dialer.NewGlobalOption(&result)
	}
	return nil
}
