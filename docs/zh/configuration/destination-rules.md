# rules / DNAT

`rules` 根据原始连接信息选择实际拨号 IP，不修改 DNS 请求或应答。它独立于 MITM、JS 和 Surge 开关。

```text
rules {
  domain(full: api.example.com) && dport(443) -> dnat(198.51.100.20)
  sip(192.168.10.0/24) && dip(192.0.2.0/24) -> dnat(198.51.100.30)
  ipversion(6) && domain(suffix: example.net) -> dnat('2001:db8::20')
}
routing {
  fallback: direct
}
```

过滤条件复用现有 routing 代码，包括 domain、dip、sip、sport、dport、l4proto、ipversion、mac、client、pname、interface、dscp、别名、取反、多值、`&&` 和数据集展开。右侧目前仅接受 `dnat(ip)`：一个 IPv4/IPv6 字面量，不能带端口、CIDR 或 zone，也不能使用域名或路由动作参数。

规则按原生配置顺序在前、插件及其内部顺序在后排列，首个匹配决定目标，保留原端口。TCP 每连接决策一次；被捕获的 UDP 按原始源、目的和接口隔离 association，固定实际目标并还原回包来源。A → B 和 B → C 不会把访问 A 的连接继续改写到 C。

普通 routing 始终查看原始连接信息，继续决定出站、mark、must 和回退；block 优先。原生 DNAT 对 direct 和 proxy 都有效。应用层 Host、TLS SNI 和证书验证名称保持原有语义。选中目标失败会使连接失败，不静默换回原 IP。

域名取自本连接可嗅探的 TLS SNI、HTTP Host 或 QUIC。内核先按不依赖域名的条件保守捕获，再在用户态精确判断；无法取得主机名时，含 domain 的规则（包括取反规则）不匹配，继续检查后续规则。原来的 DNS 路由歧义处理仍按原有机制执行。此功能不会移除已有 DNS 子系统。

活跃 UDP 映射通过独立内核 ownership map 在规则重载后继续捕获；普通 UDP 路由缓存清理不会撤掉它。节点替换时重新选择当前配置的出站，但保留 association 已选定的实际目标，包括原先没有应用 direct-only Host 映射的情况。结束后释放映射；守护进程全新启动会清除遗留 ownership。重载前完全绕过用户态的 UDP 流无法继承用户态 association 状态。

仅覆盖现有 TCP/UDP 转发路径；不提供 ICMP NAT、HTTP/3 解密或额外的 IP 分片转发。涉及 ECH 或无法嗅探的协议时，可以使用 IP、端口、来源等不依赖域名的规则。保守捕获与精确谓词共用内核匹配表预算，规则过大在准备阶段报错。

Surge `[Host]` 会转换成同一目的地址计划。支持域名、通配符、IP 到一个或多个 IP，默认只用于 direct；`use-local-host-item-for-proxy = true` 可用于 proxy。不支持的 DNS 设置有明确诊断，见 [Surge 支持范围](surge-module-support.md)。
