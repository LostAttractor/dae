// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"net"
	"testing"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	outbound "github.com/daeuniverse/dae/pkg/outbound/common"
)

func TestInstallDefaultResolver(t *testing.T) {
	original := net.DefaultResolver
	bootstrap := outbound.BootstrapResolver
	t.Cleanup(func() {
		net.DefaultResolver = original
		outbound.BootstrapResolver = bootstrap
	})

	if _, err := InstallDefaultResolver(consts.TproxyMark, ""); err == nil {
		t.Fatal("InstallDefaultResolver accepted TproxyMark")
	}
	if net.DefaultResolver != original || outbound.BootstrapResolver != bootstrap {
		t.Fatal("invalid resolver mark changed global resolver state")
	}

	r, err := InstallDefaultResolver(common.InternalSoMarkFromDae, "192.0.2.53")
	if err != nil {
		t.Fatal(err)
	}
	configured := net.DefaultResolver
	if configured == original || !configured.PreferGo || configured.Dial == nil {
		t.Fatal("InstallDefaultResolver did not install the marked Go resolver")
	}
	r.SetRoute(nil)
	if net.DefaultResolver != configured {
		t.Fatal("policy update replaced net.DefaultResolver")
	}
	if outbound.BootstrapResolver != r.Bootstrap || r.Bootstrap == r.Resolver {
		t.Fatal("proxy bootstrap did not get its own resolver")
	}
}
