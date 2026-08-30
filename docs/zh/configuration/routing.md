# 路由

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

`filter: name(name)` 是节点属性过滤，可以匹配多个定义。独立的 `node(name)` stage 是严格类型引用，节点不存在或重名时会报错。`group(name)` 严格引用一个无 `policy` group；selector group 不能嵌套为 path stage。即使 node 和 group 同名，类型化引用也没有歧义。

展开顺序首先按 path 声明顺序，然后在每条笛卡尔路径内采用 terminal-major。`entry-1`、`entry-2` 后接 `exit-1`、`exit-2` 时，顺序为 `entry-1 -> exit-1`、`entry-2 -> exit-1`、`entry-1 -> exit-2`、`entry-2 -> exit-2`。`fixed(n)` 按这个稳定的完整路径列表索引。分别声明的相同物理路径仍是不同候选。

不同路径 stage 的 `priority` 和 `add_latency` 会累加。dae 会同时开始所有路径的首次连通性检查；每个参与启动等待的 group 一旦出现可用路径，就不再阻塞启动，其余检查继续在后台运行。启动完成前，延迟策略会忽略 `check_tolerance`，因此后返回的首次检查结果仍可替换临时候选。始终没有可用路径的 group 会在全局 60 秒启动超时后留在后台继续检查。`check_async` 是节点选项，不再是路径 annotation；应在本地节点或订阅节点 option rule 上配置。完整路径中任一 hop 启用该选项时，其首次连通性检查会异步执行。当一个 group 的相关路径全部启用 `check_async` 时，该 group 完全不参与启动等待。

```shell
node {
    slow_node: 'socks5://proxy.example:1080' [check_async: true]
}

subscription {
    provider {
        link: 'https://example.com/subscription'
        option {
            check_async: true
            filter: name(fast_node) [check_async: false]
        }
    }
}
```

订阅默认值最先应用，随后按声明顺序应用所有匹配的 option rule，因此后面的 rule 可以用显式 `false` 覆盖 `true`。

旧的 `[via: ...]` annotation 会被拒绝。每个 node 仍只能包含一个分享链接；代理链统一使用 group path expression 组合。

旧的 `must_name` 简写仍然可用。如果真实节点或 group 名称以 `must_` 开头，请使用引号（例如 `'must_edge'`）按字面名称引用。

为限制连通性检查和 runtime 的资源增长，每条路径最多包含 16 跳；单个路由目标最多展开 4096 条路径；一份配置最多物化 16384 条路径。

## TCP/UDP 分片

dae 仅在无 mark 的直连、无 mark 的直通或可信控制平面路径上支持 TCP 和 UDP 分片。直通适用于已建立的入站 UDP 流，或尚无连通性状态的出站。dae 不会把非首片的载荷解析为传输层头。若首片被路由至代理、`block` 或 `direct(mark: ...)`，dae 会丢弃首片，使报文无法经不同路径重组。必须使用代理时应避免 IP 分片，并调整应用或隧道 MTU。

## 例子

```shell
### 内置出站: block, direct, must_rules

# must_rules 表示不将DNS流量重定向至dae并继续匹配。
# 对于单条规则，"direct"和"must_direct"的区别在于"direct"会劫持并处理DNS请求（用于流量分割使用），而"must_direct"不会。
# 当存在 DNS 请求的回环时，"must_direct"很有用。
# "must_direct" 也可以写作 "direct(must)"。
# 同样，"must_groupname"也支持不劫持、处理 DNS 流量，相当于"groupname(must)"。

### fallback 出站
# 如果没有规则匹配，流量将通过fallback出站.
fallback: my_group

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
# 它可以像 "must" 一样作为裸参数书写，也可以显式给出值：
domain(geosite:category-games) -> game_proxy(skip_while_noalive)
domain(geosite:category-games) -> game_proxy(skip_while_noalive: true)
# 注意：
# - 该规则级注解优先于全局 "no_connectivity_try_sniff"：目标不可用时立即跳过规则；未带该注解的规则仍遵循全局配置。
# - 只允许用于用户自定义 group 和直接节点目标。"direct" 和 "block" 不参与连通性检查，对它们使用该注解会导致配置错误。
# - 不能用于 fallback 规则。
# - 可以与其他参数组合，例如 -> my_group(must, skip_while_noalive)。

### Must规则
# 使用下面给出的规则，DNS请求将被强制重定向到dae，除了来自mosdns的请求。
# 与must_direct/must_my_group不同，来自mosdns的流量将继续匹配其他规则。
pname(mosdns) -> must_rules
ip(geoip:cn) -> direct
domain(geosite:cn) -> direct
fallback: my_group
```
