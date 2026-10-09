# 路由

`routing` 选择出站；按相同过滤语法覆盖拨号 IP 时，使用独立的 [`rules` / DNAT](destination-rules.md) 段，不能将 `dnat` 写作 routing 的出站。

## 出站目标与代理路径

路由目标可以是内置出站、group 或唯一命名的节点。名称包含空格或非 ASCII 字符时需要加引号，参数直接写在引号名称之后：

```shell
domain(full: special.example) -> '香港 01'(skip_while_noalive)
fallback: '香港 01'(mark: 0x800)
```

group 中每条语句定义一个候选代理路径。使用 `->` 按客户端到目标地址的实际代理顺序连接 stage。stage 可以当场过滤全局节点池，也可以严格引用一个节点或可复用 group：

```text
path  := stage ("->" stage)*
stage := "filter:" filter-expression annotation?
       | node(name) annotation?
       | group(name) annotation?
```

配置 `policy` 的 group 会在展开后的所有完整路径上执行选择；不配置 `policy` 的 group 可由 `group(name)` 作为路径模板复用，当它恰好展开为一条路径时也能直接作为路由目标。

```shell
group {
    relay {
        filter: name(relay-node)
    }

    proxy_jp {
        # 单 stage 直连候选。
        filter: name(lightsail) [priority: 1]

        # 直接使用 filter 组成代理链。
        filter: name(lightsail) -> filter: subtag(flowercloud) && name(keyword: '日本')

        # 无 policy group 可以作为 stage 复用。
        group(relay) -> filter: subtag(exit) [add_latency: 20ms]
        policy: min_moving_avg
    }
}
```

每条 path 语句彼此独立，因此直连 `lightsail` 和链式候选会同时存在。每个 filter stage 展开为所有匹配节点；多个 stage 做笛卡尔积；被引用的 group 会贡献其中声明的全部路径。

`filter: name(name)` 是节点属性过滤，可以匹配多个定义。独立的 `node(name)` stage 始终引用原始节点，节点不存在或重名时会报错。`group(name)` 严格引用一个无 `policy` group；selector group 不能嵌套为 path stage。

group 未声明路径或 filter 时，默认选择唯一的同名节点；没有同名节点时，选择全部节点作为独立的单跳候选路径；多个同名节点会报歧义。显式声明路径或 filter 会覆盖此默认规则。

group 与节点同名时，只有 group 展开为一条经过该唯一节点的单跳路径，路由才会优先选择 group；其他同名情况会报歧义。因此，可以保留路由目标名称并配置 group 属性：

```shell
node { foo: 'socks5://proxy.example:1080' }
group { foo { check_async: true } }
routing { fallback: foo }
```

展开顺序首先按 path 声明顺序，然后在每条笛卡尔路径内采用 terminal-major。`entry-1`、`entry-2` 后接 `exit-1`、`exit-2` 时，顺序为 `entry-1 -> exit-1`、`entry-2 -> exit-1`、`entry-1 -> exit-2`、`entry-2 -> exit-2`。`fixed(n)` 按这个稳定的完整路径列表索引。分别声明的相同物理路径仍是不同候选。

同一份运行配置内，完整代理链、节点连接参数、入口接口/有效 mark/地址族、全局传输参数，以及 `udp_check_dns`、`check_interval`、`check_interval_max` 相同的候选，共享连接池、连通性探测和恢复状态。组的 `policy`、`priority`、`add_latency`、延迟计算参数和 `check_tolerance` 独立生效，流量统计、候选 ID 和手动选择也按组保留。因此两个组引用相同路径时可以共享节点健康状态，但组可用率仍取决于各自的候选和选择策略。

任一组持续监测共享路径，探测就保持运行；某个 selector 切走或某个组关闭不会停止其他组需要的探测。手动探测请求按共享路径合并，结果对引用它的组可见。所有组都释放路径后才停止探测，已有连接及持有运行时的调用者按原生命周期排空。reload 的候选配置使用独立运行时，以隔离准备阶段的连接、探测与统计发布。

不同路径 stage 的 `priority` 和 `add_latency` 会累加。自动策略按故障降级状态和优先级分层检查候选，出现已验证的选择或本轮候选耗尽后解除启动等待。`fixed(n)` 只等待索引为 `n` 的路径。全局启动兜底超时为 60 秒。按需故障切换使用 `policy: failover`；探测范围、升级回切、故障降级和状态含义见[自动节点选择](outbound-selection.md)。

连通模式一旦确认，dae 会保留该能力。节点使用一个已支持模式执行常规健康检查，其健康状态由所有已支持模式共享。

启动完成前，延迟策略会忽略 `check_tolerance`；每个新确认的模式也会额外忽略一次，使后续新连接能够修正选择。已有连接仍保留原 outbound。

`check_async: true` 使整个 group 的首次检查都不阻塞启动。所有生效路由引用都配置 `skip_while_noalive` 时默认开启；存在任何未配置该参数的生效引用（包括 `fallback`）时默认关闭。显式 `true` 或 `false` 覆盖默认值。直接作为路由目标的节点使用相同默认规则。`group(name)` 不继承此设置，仅作为模板的 group 不能配置它。

只有默认策略、接口绑定策略、它们递归 `use` 的 `rule_set` 或插件路由引用的 group 和直接路由节点才会创建运行时出站。仅被未启用定义引用的目标仍会校验，但不会创建运行时出站、启动健康检查，也不会出现在状态和 selector API 中。模板依赖展开到生效目标的完整路径中。是否使用按配置引用判定，与当前流量或连通性无关；reload 时重新计算，并保留手动 selector 选择，以便重新启用时恢复。

每个 node 只能包含一个分享链接；代理链使用 group path expression 组合。

如果真实节点或 group 名称为 `must` 或以 `must_` 开头，请使用引号（例如 `'must_edge'`）按字面名称引用。流量控制配置在 `rules {}` 中。

为限制连通性检查和 runtime 的资源增长，每条路径最多包含 16 跳；单个路由目标最多展开 4096 条路径；一份配置最多物化 16384 条路径。

### 入口 mark、接口和地址族

```shell
group {
    proxy {
        filter: subtag(my_sub) [mark: 0x20, interface: wan0]
        policy: min_moving_avg
    }
    ipv4_only {
        filter: subtag(my_sub) && ipversion(4) [interface: wan1]
        policy: min_moving_avg
    }
    chain {
        filter: name(entry) && ipversion(6) [mark: 0x30, interface: wan0] -> node(exit)
        policy: min_moving_avg
    }
}
```

- `mark` 设置入口 socket 的 `SO_MARK`，支持十进制、十六进制 uint32，禁止包含保留的 TPROXY 位 `0x08000000`。省略时继承 `global.so_mark_from_dae` 的有效值；显式 `mark: 0` 使用零。它与 routing 规则的 `mark` 参数相互独立。
- `interface` 使用 `SO_BINDTODEVICE` 绑定接口。入口 TCP、UDP、QUIC、测速、重连和 bootstrap DNS（包括 TCP DNS 重试）使用相同 mark/interface。创建候选前检查接口能力；已有候选若绑定失败，则本次操作失败并沿用健康检查重试。
- 回环 DNS（如 `127.0.0.1`、`127.0.0.53`、`::1`）通过本机连接访问，不绑定代理出口接口，但保留入口 mark。系统 DNS 和 `global.dns_resolver` 均遵循此规则；本地 DNS 服务自行决定上游出口。外部 DNS 和所有代理连接仍使用配置的接口。
- `ipversion(4)` / `ipversion(6)` 严格限制连接入口代理的地址族；`ipversion(4, 6)` 允许双栈，支持通常的取反和交集语义。DNS 传输自身可独立使用任一地址族。它不限制代理访问目标的地址族，也不改变 TLS SNI / HTTP Host。
- 三项设置只允许出现在第一物理 stage，嵌套 `group(name)` 展开后同样检查。`mark`、`interface` 注解也可写在入口 `node(name)`、`group(name)` 引用上。嵌套注解冲突、后续 stage 配置这些选项都会报错。

启动/reload 时，先通过入口配置的 bootstrap DNS 出口解析节点。只有该地址族存在解析地址，且内核能够按配置的 mark 在本机/指定接口上选出可用路由和源地址，才创建对应候选。两个地址族均满足条件时，域名节点才拆成 IPv4、IPv6 两个候选（IPv4 在前）。仅 A 记录的节点、本机/接口仅支持 IPv4、接口仅有链路本地 IPv6 地址等情况，不会生成 IPv6 占位节点。IP 字面量同样检查本地条件。候选分别维护健康、延迟、统计和连接池；同一地址族中的多个地址属于同一个候选。名称和订阅过滤仍匹配原始节点定义。DNS 或本地网络地址族能力变化后，通过 reload 重新发现候选；已有候选的连通性变化仍由健康检查处理。

地址族展开在逻辑路径展开之后进行，并计入路径数量限制。`fixed(n)`、`selector(n)` 索引展开后的列表；需要固定地址族时使用 `ipversion()`。routing 直接引用节点、或无 policy 的单逻辑路径，在双栈变体之间默认使用 `min_moving_avg`；显式 policy 始终优先。状态和 selector API 提供 `egress`（`ipversion`、有效 `mark`、可选 `interface`）；显示名称仅在双栈拆分时标注 IPv4/IPv6，单栈不标注。候选 ID 包含地址族和入口选项，DNS 变化及重新排序不改变 ID。

## 规则片段、路由策略与接口绑定

`rule_set` 定义可复用的规则片段，`policy` 定义包含 fallback 的完整路由策略，`default` 和 `interface` 选择策略：

```shell
routing {
    rule_set {
        local {
            dip(geoip:private) -> direct
        }
        china {
            dip(geoip:cn) -> direct
            domain(geosite:cn) -> direct
        }
    }
    policy {
        main {
            use: local, china
            fallback: proxy
        }
        lan {
            use: local
            fallback: direct
        }
    }
    default: main
    interface {
        br-lan: lan
        eth1: lan
        wg0: main
    }
}
```

- `use: local, china` 按顺序插入两个片段，等价于连续两条 `use`。`use` 可以与普通规则交错，片段还可以引用其他片段；不能引用策略，也不能循环引用。
- 片段只包含规则和 `use`，不能包含 `fallback`。每个策略必须且只能声明一个 `fallback`。它在所有规则均未命中后执行，与该字段在策略内的书写位置无关。
- `default: main` 为没有接口绑定的流量选择 `main`；`interface` 中每行将一个精确设备名绑定到命名策略。多个接口及默认路由可以选择同一个策略，它只编译一次。
- 每个接口名只能绑定一次，即使重复选择同一策略也会报错。含特殊字符的接口名可以加引号，例如 `"foo,bar": lan`；不支持通配符匹配。接口重建后会自动更新 ifindex。
- 策略彼此独立，不继承默认策略。绑定只选择路由规则，接管流量仍需配置 `global.lan_interface` / `global.wan_interface`。单条规则内仍可使用 `interface(name)` 条件。
- 策略名和片段名属于不同的命名空间；未定义引用、重复声明或循环引用都会报错。

只需要一个默认策略时，可以直接在 `routing` 中写规则、`use` 和一个 `fallback`：

```shell
routing {
    rule_set {
        local { dip(geoip:private) -> direct }
    }
    use: local
    fallback: proxy
}
```

这种写法是匿名默认策略，可与 `rule_set`、命名 `policy` 和 `interface` 声明共存，但不能同时设置 `default: 策略名`。匿名默认策略也必须显式声明 fallback。

### 为规则片段添加公共条件

使用 `条件 -> use(片段名)`，给引用片段中的所有规则附加同一个条件：

```shell
routing {
    rule_set {
        office {
            domain(suffix: corp.example) -> proxy
            dip(10.20.0.0/16) -> proxy
            dport(853) -> block
        }
        tcp_office {
            l4proto(tcp) -> use(office)
        }
    }

    sip(192.168.10.0/24) -> use(tcp_office)
    fallback: direct
}
```

此例中，`office` 的每条规则都需要同时满足 `sip(192.168.10.0/24)`、`l4proto(tcp)` 和自身的条件。公共条件不成立，或片段中所有规则均未命中时，继续匹配 `use` 后面的规则。

- 支持现有 routing 条件，包括 `client()`、`interface()`、`domain()`、`!`、`&&` 和函数内的多值匹配。例如 `client(work) && !l4proto(udp) -> use(office)`。
- `条件 -> use(a, b)` 按顺序引用 a 和 b，条件对两者都生效。仍可使用 `use: a, b` 无条件引用。
- 条件可写在匿名默认策略、命名策略或规则片段内；嵌套引用时，各层条件与最终规则条件取 AND。同名函数的条件也取交集，例如外层 `dport(80,443)` 与内层 `dport(443,853)` 只匹配 443。
- 片段内部的出站、mark 和 `skip_while_noalive` 保留原有语义；fallback 仍由所属策略在所有规则未命中后执行。条件引用不能作为 fallback。
- `use(...)` 的参数只能是规则片段名称。若出站本身名为 `use` 且需要参数，写作 `'use'(mark: 0x800)`；不带参数的 `-> use` 仍表示同名出站。
- 导出配置保留条件和引用，多个片段可以导出为连续的条件引用。相同片段与相同已规范化条件序列共享编译结果；不同条件生成不同版本，其指令计入规则容量限制。每次编译的片段与条件组合数也受 `MaxMatchSetLen` 限制。

公共条件直接编入内核和用户态路由规则。`domain()` 沿用已有域名—IP 映射及否定匹配语义：缺少 DNS 映射时，正向域名条件不命中，不会为获取 SNI/Host 而额外捕获流量。已有 MITM、DNAT/Host 捕获和 API 直通规则仍按各自的条件执行。

### 拆分为多个文件

通过 `include` 分别维护规则片段、策略和接口绑定；每个文件保留 `routing { ... }` 外层。每个命名片段和策略只能声明一次，大型策略通过 `use` 组合更小的片段。引用可以先于声明；执行顺序由策略内的规则和 `use` 决定，与声明文件顺序无关。导出配置会保留引用和执行顺序，并将 fallback 写在策略末尾。完整示例见[拆分配置文件](separate-config.md)。

配置最多包含 1024 个片段及策略、65536 条原始规则及 use 语句、256 个接口绑定，引用深度最多 64 层。共享物理规则池和每套策略的执行长度分别受 `MaxMatchSetLen` 限制（默认 1024）。未使用的片段和策略也会校验，但不占用活动策略的内核规则池，也不会注册接口监听。

### MITM、DNAT 与 Host 的共享捕获片段

启用 MITM 插件、原生 `rules { ... -> dnat(ip) }` 或 Surge Host 后，dae 自动生成内部捕获与流量控制片段，供所有策略共享，无需手动添加规则或 `use`。

执行顺序为：API 本机访问直连 → DNAT/Host 与请求型 HTTP 捕获 → `rules` 中的 must/bump 与纯 MITM 捕获 → 模块 `pre-matching` 规则 → 用户策略规则 → 普通模块规则 → 策略 fallback。所有策略共享同一段捕获与流量控制指令，策略继续决定出站、mark 和 block。MITM 保留插件声明的域名/IP 与对应端口；DNAT/Host 保留完整过滤条件，包括域名。缺少 DNS 映射不会隐式扩大捕获范围，无关 direct 流量保持内核直通。目的地址的用户态精确匹配不占用内核指令槽位，相同域名和静态 IP 条件跨阶段共享。

DNAT/Host 候选命中后，内核在执行 flow/routing 前交接用户态。目标规则按输入目标选定新 IP，后续 flow/routing 使用重写后的目的地址和地址族，保留来源、接口、进程及策略身份；候选未精确命中则继续使用原目标。纯 MITM 检查保留已确定的路由。需要请求路由的范围（Surge 的脚本、URL Rewrite、Map Local）同样提前交接：客户端准入后先执行 HTTP 处理，再按最终目标执行目标规则、flow 和 routing，原目标 block 不抢先终止请求。每个请求在连接池查找前确定路由，池按实际目标、节点、出站和 mark 隔离。详见 [DNAT 行为](destination-rules.md#dnat-行为)与 [MITM 插件](mitm-plugins.md)。

策略 ID 只在所属配置代内有效，默认路由和接口引用同一策略时共享该 ID；交接中的 generation 选择对应的配置解释器。UDP 按源 IP 和源端口维护生命周期，活动源保留首次选定的策略及路由，不因调整绑定、切换默认策略或重建接口而立即重路由。生命周期结束后，下一次报文才按当前绑定选路；各代独立 DNS relay 的重新路由合并键包含策略 ID，避免不同策略的请求混用决策。

## 手动选择与设备集合

`policy: selector` 允许手动选择节点，默认选择第一个，也可用 `selector(n)` 指定默认索引。`client(name)` 匹配设备自行加入的 MAC 集合。配置与使用见[页面/API](api.md)。

## TCP/UDP 分片

dae 仅在无 mark 的直连、无 mark 的直通或可信控制平面路径上支持 TCP 和 UDP 分片。直通适用于已建立的入站 UDP 流，或尚无连通性状态的出站。dae 不会把非首片的载荷解析为传输层头。若首片被路由至代理、`block` 或 `direct(mark: ...)`，dae 会丢弃首片，使报文无法经不同路径重组。必须使用代理时应避免 IP 分片，并调整应用或隧道 MTU。

## 例子

`geoip.dat` 和 `geosite.dat` 按规则引用分别加载；没有引用时无需安装，也不会读取。
普通 IP/CIDR、域名、端口等规则不依赖它们。具名规则片段、策略及插件规则中的引用也需要对应文件；
`ext:` 和 `mmdb:` 只读取指定的数据文件。被引用的文件缺失或损坏会导致规则准备失败。

```shell
### 内置出站: block, direct
# 流量控制 must 和 bump 配置在独立的 rules {} 中。

### fallback 出站
# 如果没有规则匹配，流量将通过fallback出站.
# fallback: my_group

### 域名规则
domain(suffix: v2raya.org) -> my_group # 相当于 domain(v2raya.org) -> my_group 
domain(full: dns.google) -> my_group
domain(keyword: facebook) -> my_group
domain(regex: '\.goo.*\.com$') -> my_group
domain(geosite:category-ads) -> block
domain(geosite:cn)->direct

### 目标 IP 规则
dip(8.8.8.8) -> direct
dip(101.97.0.0/16) -> direct
dip(geoip:private) -> direct

### 源 IP 规则
sip(192.168.0.0/24) -> my_group
sip(192.168.50.0/24) -> direct

### 目标端口规则
dport(80) -> direct
dport(10080-30000) -> direct

### 源端口规则
sport(38563) -> direct
sport(10080-30000) -> direct

### 四层协议规则:
l4proto(tcp) -> my_group
l4proto(udp) -> direct

### IP版本规则:
ipversion(4) -> block
ipversion(6) -> ipv6_group

### 源MAC地址规则
mac('02:42:ac:11:00:02') -> direct

### 进程名称规则（绑定WAN时仅支持本机进程）
pname(curl) -> direct

### DSCP规则（匹配 DSCP，可用于绕过 BT），见 https://github.com/daeuniverse/dae/discussions/295
dscp(0x4) -> direct

### 入站接口规则
interface(br-lan) -> direct

### 多个域名规则
domain(keyword: google, suffix: www.twitter.com, suffix: v2raya.org) -> my_group
### 多个IP规则
dip(geoip:cn, geoip:private) -> direct
dip(9.9.9.9, 223.5.5.5) -> direct
sip(192.168.0.6, 192.168.0.10, 192.168.0.15) -> direct

### "并"规则
dip(geoip:cn) && dport(80) -> direct
dip(8.8.8.8) && l4proto(tcp) && dport(1-1023, 8443) -> my_group
dip(1.1.1.1) && sip(10.0.0.1, 172.20.0.0/16) -> direct

### "非"规则
!domain(geosite:google-scholar,
        geosite:category-scholar-!cn,
        geosite:category-scholar-cn
    ) -> my_group

### 更复杂一点的规则
domain(geosite:geolocation-!cn) &&
    !domain(geosite:google-scholar,
            geosite:category-scholar-!cn,
            geosite:category-scholar-cn
        ) -> my_group

### 个性化DAT文件
domain(ext:"yourdatfile.dat:yourtag")->direct
dip(ext:"yourdatfile.dat:yourtag")->direct

### 设置防火墙标记
# 当您想要将流量重定向到特定接口（例如wireguard）或用于其他高级用途时，标记非常有用。
# 这里给出了将 Disney 流量重定向到 wg0 的示例。
# 您需要像这样设置 ip 规则和 ip 路由表：
# 1. 将所有标记为 0x800/0x800 的流量设置为使用路由表 1145：
# >> ip rule add fwmark 0x800/0x800 table 1145
# >> ip -6 rule add fwmark 0x800/0x800 table 1145
# 2. 设置路由表1145的默认路由：
# >> ip route add default dev wg0 scope global table 1145
# >> ip -6 route add default dev wg0 scope global table 1145
# 注意：接口wg0，标记0x800，表1145可以通过首选项设置，但不能冲突。
# 3. 在dae配置文件中设置路由规则。
domain(geosite:disney) -> direct(mark: 0x800)

### 目标 group 不存活时跳过规则
# 如果一条规则带有 "skip_while_noalive" 注解，那么只有当目标 group 可用时，该规则才
# 生效。当 group 不可用时，该规则被视为未命中，路由继续向下匹配后续规则（直至
# fallback）。
# 当你希望特定流量走特定出口、但这并非必需时很有用：出口故障时流量会透明地降级到
# 通用规则。
# 它可以作为裸参数书写，也可以显式给出值：
domain(geosite:category-games) -> game_proxy(skip_while_noalive)
domain(geosite:category-games) -> game_proxy(skip_while_noalive: true)
# 注意：
# - 该规则级注解优先于全局 "no_connectivity_try_sniff"：目标不可用时立即跳过规则；未带该注解的规则仍遵循全局配置。
# - 只允许用于用户自定义 group 和直接节点目标。"direct" 和 "block" 不参与连通性检查，对它们使用该注解会导致配置错误。
# - 不能用于 fallback 规则。
# - 可以与其他参数组合，例如 -> my_group(mark: 0x1000, skip_while_noalive)。

```

## Bridge 成员接口匹配

`interface(name)` 同时匹配捕获接口和内核 bridge netfilter 保存的入口成员接口（`physinif`）。例如，`global.lan_interface: br-lan`，且 `br-lan` 下有 `lan`、`direct` 两个成员时：

```text
routing {
    interface(direct) -> direct
    interface(lan) -> my_group
    fallback: direct
}
```

`interface(br-lan)` 可以匹配两边的流量。多值条件匹配任一接口即可；`!interface(lan,direct)` 表示捕获接口和入口成员均未匹配这些名称。尚未存在的接口不会以索引 `0` 命中。

成员信息依赖内核 `CONFIG_BRIDGE_NETFILTER`、`br_netfilter` 模块以及对应协议的 bridge netfilter 路径，例如 IPv4 的 `net.bridge.bridge-nf-call-iptables=1`、IPv6 的 `net.bridge.bridge-nf-call-ip6tables=1`。dae 只读取已有信息，不自动开启这些选项。没有 `physinif` 时只匹配捕获接口；普通 `ingress_ifindex` 在 bridge 上通常已经被改为 bridge 自身。VLAN 等封装还取决于相应 bridge netfilter 设置。

入口成员身份会随路由结果保留到 UDP 缓存及用户态重路由。策略的接口绑定仍按捕获接口选择策略，`interface()` 在选中的策略内匹配。

## `rules {}` 中的流量控制

`must` 跳过自动 DNS 接管，继续由普通路由选择出站。`bump` 要求用户态重新路由，出站和 mark 仍由 `routing {}` 决定。它们独立于 MITM，可同时命中，不依赖书写顺序。`must` 不会取消显式的 `bump`、MITM 或 DNAT 捕获。 整个控制段执行完后才决定是否进入用户态；域名歧义不会遮蔽后续确定性 must 或捕获动作。

```text
rules {
    pname(mosdns) -> must
    domain(full: api.example.com) && l4proto(tcp) -> bump
}
routing {
    ip(geoip:cn) -> direct
    domain(geosite:cn) -> direct
    fallback: my_group
}
```

正向域名规则需要已有 DNS 映射才能选中原本的内核直连；未命中的 direct 流量保持 eBPF 直通，不为取得主机名增加全流量捕获。共享 IP 歧义和取反条件沿用原有域名匹配语义。

流量控制配置在 `rules {}` 中，并显式写出适用条件；`routing {}`（包括 `fallback`）选择出站及其参数。控制条件在全部普通路由之前判断。DNAT 与控制动作的组合见 [rules 配置](destination-rules.md)。
