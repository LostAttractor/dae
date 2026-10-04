module github.com/daeuniverse/dae

go 1.27.0

require (
	github.com/adrg/xdg v0.5.3
	github.com/andybalholm/brotli v1.2.4
	github.com/antlr4-go/antlr/v4 v4.13.1
	github.com/bits-and-blooms/bloom/v3 v3.7.1
	github.com/buke/quickjs-go v0.7.8-0.20260823090719-48da2085b266
	github.com/cilium/ebpf v0.22.0
	github.com/daeuniverse/dae-config-dist/go/dae_config v0.0.0-20230604120805-1c27619b592d
	github.com/daeuniverse/outbound v0.0.0-20250722064253-00c4fbb38759
	github.com/daeuniverse/quic-go v0.0.0-20250210145620-2083199a7851
	github.com/dlclark/regexp2 v1.12.0
	github.com/fsnotify/fsnotify v1.10.1
	github.com/google/go-cmp v0.7.0
	github.com/google/nftables v0.3.0
	github.com/itchyny/gojq v0.12.19
	github.com/jedib0t/go-pretty/v6 v6.8.3
	github.com/miekg/dns v1.1.73
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826
	github.com/okzk/sdnotify v0.0.0-20240725214427-1c1fdd37c5ac
	github.com/oschwald/maxminddb-golang/v2 v2.6.0
	github.com/prometheus/client_golang v1.24.1
	github.com/prometheus/client_model v0.6.3
	github.com/robfig/cron/v3 v3.0.1
	github.com/shirou/gopsutil/v4 v4.26.8
	github.com/sirupsen/logrus v1.10.2
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.10
	github.com/stretchr/testify v1.12.1
	github.com/v2rayA/ahocorasick-domain v0.0.0-20231231085011-99ceb8ef3208
	github.com/vishvananda/netlink v1.3.1
	github.com/vishvananda/netns v0.0.5
	github.com/xtaci/smux v1.5.57
	golang.org/x/crypto v0.57.0
	golang.org/x/exp v0.0.0-20260908205506-85c1c2202aba
	golang.org/x/net v0.59.0
	golang.org/x/sync v0.23.0
	golang.org/x/sys v0.48.0
	golang.org/x/term v0.46.0
	google.golang.org/protobuf v1.36.12
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
)

require (
	github.com/awnumar/fastrand v0.0.0-20210315215012-30ee0990fa2d // indirect
	github.com/awnumar/memcall v0.5.0 // indirect
	github.com/awnumar/memguard v0.23.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bits-and-blooms/bitset v1.25.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/clipperhouse/stringish v0.1.1 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/dgryski/go-camellia v0.0.0-20191119043421-69a8a13fb23d // indirect
	github.com/dgryski/go-idea v0.0.0-20170306091226-d2fb45a411fb // indirect
	github.com/dgryski/go-rc2 v0.0.0-20150621095337-8a9021637152 // indirect
	github.com/ebitengine/purego v0.11.0 // indirect
	github.com/eknkc/basex v1.0.1 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/itchyny/timefmt-go v0.1.8 // indirect
	github.com/klauspost/compress v1.20.0 // indirect
	github.com/klauspost/cpuid/v2 v2.4.0 // indirect
	github.com/mattn/go-runewidth v0.0.30 // indirect
	github.com/mdlayher/netlink v1.11.2 // indirect
	github.com/mdlayher/socket v0.7.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/power-devops/perfstat v0.0.0-20260916180654-3a94d42856b1 // indirect
	github.com/prometheus/common v0.71.0 // indirect
	github.com/prometheus/procfs v0.22.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	gitlab.com/yawning/chacha20.git v0.0.0-20230427033715-7877545b1b37 // indirect
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/tools v0.50.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260911204522-f61a6ca850bd // indirect
	google.golang.org/grpc v1.83.2 // indirect
	lukechampine.com/blake3 v1.4.1 // indirect
)

replace (
	github.com/buke/quickjs-go => ./third_party/quickjs-go
	github.com/daeuniverse/dae-config-dist/go/dae_config => ./third_party/dae-config-dist/go/dae_config
	github.com/daeuniverse/outbound => ./third_party/outbound
	github.com/daeuniverse/quic-go => ./third_party/quic-go
)
