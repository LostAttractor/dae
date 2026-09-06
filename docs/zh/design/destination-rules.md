# DNAT 实现说明

配置和行为见 [rules / DNAT](../configuration/destination-rules.md)。

`config.Rules` 校验 dnat 的 IP 参数，`prepareDestinationRules` 单独执行谓词规范化，保留规则顺序。`RulesBuilder.ApplyPredicate` 与普通路由共用函数解析和逻辑边，目标 IP 不进入 outbound ID 命名空间。

`RoutingMatcherBuilder` 生成两部分：在普通路由之前收集保守捕获标志；在普通 fallback 之后放置供用户态使用的精确谓词。domain 在候选条件中被投影掉，包括取反的 domain；其它条件继续限制捕获。精确匹配保留完整原始谓词，unknown domain 不证明正向或反向匹配。两个部分共用集合、client/interface 引用与匹配表预算。

内核 routing_result 的原填充字节保存 capture_flags 和 protocol，结构体大小不变。捕获累积到独立标志，不替换普通路由的 outbound、mark、must；目的 IP 到拨号目标的改变在 Go 连接层执行。

UDP association 使用源地址、原目的和接口作为隔离键。用户态在独立 pinned map 中持有捕获 ownership；连接关闭时按 owner token 删除，延迟关闭旧 socket 不会删除后继 ownership。持有的是 map 的克隆描述符，不是退休控制面。全新启动清理遗留映射，热重载保留活动 ownership。节点替换重算当前出站索引，沿用已固定的实际目标。

当前不提供包头 NAT、ICMP、额外分片处理或 HTTP/3 解密。未经过用户态的既有 UDP 流没有可继承的 association。DNS 路由原有的歧义验证仍独立存在；本次没有移除 DNS 子系统。

消融后删除了 `From` 字面 IP 专用表示、`Lookup/Rewrite` 备用执行器、`KeepOriginal` 兼容屏障，以及依赖 DNS 重新推演捕获前路由的分支。所有映射只有 `Filter + To + Proxy` 一种形式。不支持的 Host 动作直接报错，避免改变后续规则顺序。

捕获使用普通谓词的独立标志，不再需要专用 `MatchType_Capture`，HTTP 只需一个 TCP 条件。API 绕过规则在所有捕获之前终止。用户态普通路由与精确 DNAT 共用持锁的范围求值函数和绝对 bitmap 索引，不复制整个 matcher，也没有跳过锁的模式。
