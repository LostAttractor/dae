/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	_ "github.com/daeuniverse/dae/pkg/outbound/dialer/anytls"
	_ "github.com/daeuniverse/dae/pkg/outbound/dialer/http"
	_ "github.com/daeuniverse/dae/pkg/outbound/dialer/hysteria2"
	_ "github.com/daeuniverse/dae/pkg/outbound/dialer/juicity"
	_ "github.com/daeuniverse/dae/pkg/outbound/dialer/shadowsocks"
	_ "github.com/daeuniverse/dae/pkg/outbound/dialer/shadowsocksr"
	_ "github.com/daeuniverse/dae/pkg/outbound/dialer/socks"
	_ "github.com/daeuniverse/dae/pkg/outbound/dialer/trojan"
	_ "github.com/daeuniverse/dae/pkg/outbound/dialer/tuic"
	_ "github.com/daeuniverse/dae/pkg/outbound/dialer/v2ray"
	_ "github.com/daeuniverse/dae/pkg/outbound/protocol/anytls"
	_ "github.com/daeuniverse/dae/pkg/outbound/protocol/hysteria2"
	_ "github.com/daeuniverse/dae/pkg/outbound/protocol/juicity"
	_ "github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks"
	_ "github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks_2022"
	_ "github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks_stream"
	_ "github.com/daeuniverse/dae/pkg/outbound/protocol/trojanc"
	_ "github.com/daeuniverse/dae/pkg/outbound/protocol/tuic"
	_ "github.com/daeuniverse/dae/pkg/outbound/protocol/vless"
	_ "github.com/daeuniverse/dae/pkg/outbound/protocol/vmess"
	_ "github.com/daeuniverse/dae/pkg/outbound/transport/ws"
)
