# rules：流量控制与 DNAT

`rules` 先匹配原始连接并选择 DNAT 目标，再基于重写后的目的地址执行 must/bump 和 `routing`。`routing` 选择出站及 mark；来源、接口、进程和策略身份保持不变。`rules` 独立于 MITM、JS 和 Surge 开关，不修改 DNS 请求或应答内容。

```text
rules {
  pname(mosdns) -> must
  domain(full: api.example.com) && l4proto(tcp) -> bump
  domain(full: api.example.com) && dport(443) -> dnat(198.51.100.20)
  sip(192.168.10.0/24) && dip(192.0.2.0/24) -> dnat(198.51.100.30)
  ipversion(6) && domain(suffix: example.net) -> dnat('2001:db8::20')
}
routing {
  fallback: direct
}
```

过滤条件复用现有 routing 代码，包括 domain、dip、sip、sport、dport、l4proto、ipversion、mac、client、pname、interface、dscp、别名、取反、多值、`&&` 和数据集展开。右侧支持：

| 动作 | 作用 |
| --- | --- |
| `must` | 跳过自动 DNS 接管，继续由 routing 选择出站。无参数。 |
| `bump` | 要求用户态重新路由，出站和 mark 仍由 routing 决定。无参数。 |
| `dnat(ip)` / `dnat('IP:port')` | 覆盖实际拨号目标；省略端口时保留原端口。仅接受一个 IPv4/IPv6 字面量，可指定非零端口，不接受 CIDR、zone 或域名。 |

三个动作可以同时命中。`must` 不代表强制直连，也不会取消 `bump`、MITM 或 DNAT。API 精确直通规则最先判断；随后依次处理目的地址、流量控制和普通路由。内核命中 DNAT/Host 候选后立即交给用户态，不能先用旧地址提交出站、mark、must 或 block。用户态精确匹配目标后，flow 和 routing 使用新目的 IP 和地址族，域名仍表示原 Host/SNI。未命中目的地址候选的流量沿用普通内核流程；must 和 bump 的书写顺序不影响组合，控制段结束时统一处理域名歧义。

流量控制和出站选择分别配置，控制条件在全部普通路由之前判断。例如，让指定进程跳过自动 DNS 接管并直连：

```text
rules {
  pname(naiveproxy) -> must
}
routing {
  pname(naiveproxy) -> direct
  # 其余路由和 fallback ...
}
```

MITM、原生 DNAT 和 Surge Host 的捕获条件自动编译为所有策略共享的片段，用户无需重复添加。自定义片段见[路由规则集](routing.md)。

## DNAT 行为

DNAT 规则按原生配置顺序在前、插件及其内部顺序在后排列，首个匹配决定目标；省略端口时保留原端口。用户态在 must/bump 和普通路由求值前选定目标，命中不会阻止独立的 must/bump 控制。TCP 每连接决策一次；被捕获的普通 UDP association 固定实际目标并还原回包来源。DNS 按请求透传，原端口 53 经 DNAT 改到其它端口后仍是 DNS。A → B 和 B → C 不会递归重写。

普通 routing 查看重写后的目的 IP、端口和地址族，并保留原始来源、接口、进程、MAC、DSCP、策略及 Host/SNI。新目标上的 direct/proxy/block、mark、must 和 skip_while_noalive 均重新求值；旧目标上的路由结果不会沿用。原生 DNAT 对 direct 和 proxy 都有效。应用层 Host、TLS SNI 和证书验证名称保持原有语义。选中目标失败会使连接失败，不静默换回原 IP。

例如 `dip(192.0.2.1) -> dnat(198.51.100.1)` 命中后，后续 `dip(198.51.100.1) -> proxy` 会生效；`dip(192.0.2.1) -> block` 不会抢先阻止这次目标重写。若新目标命中 block，则不拨号。目的地址候选在用户态精确匹配失败时，按原目标执行正常 flow/routing。

内核捕获保留完整过滤条件，包括 `domain()`；其域名判断与普通 routing 一样使用已有 DNS 域名—IP 映射。不会移除域名条件来扩大捕获范围，无关 direct 流量保持 eBPF 内核直通。缺少映射时，正向域名规则无法主动捕获原本的内核直连；取反条件沿用普通 routing 语义，可能选择更广的候选。

用户态按本连接可嗅探的 TLS SNI、HTTP Host 或 QUIC 精确判断；无法取得主机名时，含 domain 的规则（包括取反规则）不匹配，继续检查后续规则。DNS 的 qname 不用于把 DNS 服务器连接当作被查询网站。域名观察与持久化边界见 [DNS](dns.md)。

活动 UDP 会话在规则重载后保留已选定的实际目标；节点替换时使用这个目标重新匹配当前配置的路由。原始五元组继续用于会话隔离和回包还原。重载前完全绕过用户态的 UDP 流没有可继承的会话状态。各组件职责见[项目结构](../design/project-structure.md)。

仅覆盖现有 TCP/UDP 转发路径；不提供 ICMP NAT、HTTP/3 解密或额外的 IP 分片转发。涉及 ECH 或无法嗅探的协议时，可以使用 IP、端口、来源等不依赖域名的规则。内核加载目的地址捕获、流量控制和出站规则；目的地址精确匹配由独立的 DestinationProgram 在用户态执行，不占内核指令槽位。相同域名条件和静态 IP 集合跨阶段共享。内核指令、用户态目的地址指令和域名条件分别检查容量，规则过大在准备阶段报错。

Surge `[Host]` 的字面 IP → IP 条目转换成同一目的地址计划，对 direct 和 proxy 都生效。域名和通配符条目由 DNS 处理，不生成自动 DNAT。显式 IP 重写优先于 `dial_target_override`，Host/SNI 保持原有语义。

`use-local-host-item-for-proxy` 控制已截获代理连接是否保留域名静态 Host 的 DNS IP，见 [Surge 支持范围](surge-module-support.md)。
