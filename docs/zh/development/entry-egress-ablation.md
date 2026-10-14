# 入口发现与出口约束验证

入口发现只为 DNS 和本机路由、源地址共同支持的地址族创建候选。配置准备期间，不同组共享同一 hostname、有效 mark、绑定接口和 DNS resolver 的发现结果；reload 重新发现。每组独立应用地址族筛选、标签和选择策略，健康检查负责已有候选的后续连通性。

发现使用最多 8 个 worker。取消后停止提交排队工作；结果保持路径声明顺序。显式零 mark 覆盖全局值。IPv6 zone 必须与绑定接口一致；单栈候选不显示 IPvX 标签。

入口 TCP、UDP、QUIC、探测及 bootstrap DNS 使用相同出口约束。最终 DNS 服务器为回环地址时，DNS socket 保留 mark 并豁免接口绑定，UDP 和 TCP 重试一致；私网 DNS 仍绑定接口。判断使用实际 DNS 地址，支持原生和 IPv4-mapped 回环地址。

## 验证工具

`scripts/entry-egress-ablation.py` 通过 Go overlay 单独移除约束，并检查指定断言是否能够检出错误。它不修改生产源码或配置。编译失败、权限不足、测试跳过和进程超时均不算检出。

```sh
python3 scripts/entry-egress-ablation.py
python3 scripts/entry-egress-ablation.py --suite loopback-dns
python3 scripts/entry-egress-ablation.py --output /tmp/dae-entry-checks
```

输出目录包含 overlay、测试二进制、命令输出、源文件摘要和 `summary.json`。未指定 `--output` 时，使用系统临时目录下的 `entry-egress-ablation-*`。

- 地址族夹具控制 A/AAAA 应答，并校验实际本地路由与源地址。
- mark、接口和 IPv6 zone 夹具在独立 network namespace 中配置 dummy 接口、路由及策略规则，需要对应内核权限。
- socket 夹具读取实际 `SO_MARK` 和 `SO_BINDTODEVICE`。
- 回环 DNS 夹具使用本地 DNS 服务，覆盖系统/显式 resolver、UDP 截断后的 TCP 重试和映射地址。
- 路径夹具检查候选顺序、名称、独立 ID、注解及取消行为。

## 基准范围

CPU 夹具使用立即返回的发现函数；受控延迟夹具为每次发现加入固定等待；本地 DNS 夹具执行真实 loopback DNS 与内核查询。三类数据分别反映准备期的计算、并发和本机查询开销，不能据此推断代理转发吞吐量。

跨版本比较应固定路径数、唯一入口数、运行环境及基准时长。`--baseline-source /path/to/snapshot` 可指定入口发现源码快照；该选项用于默认 `egress` 套件。结果同时记录发现次数、查询次数和分配，避免仅凭耗时波动判断收益。
