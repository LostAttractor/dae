# 自动节点选择

`min` 使用最近成功延迟，`min_avg10` 使用最近十次成功延迟的平均值，`min_moving_avg` 使用成功样本的移动平均（可配置 `min_moving_avg(alpha: 0.18)`）。失败不写入延迟统计；没有成功样本时延迟未知。

同一优先级内，延迟策略比较 `实测统计值 + add_latency`。条件 `priority` 使用未加偏移的实测值。`check_tolerance` 只用于同层延迟比较。

Prometheus 的 `dae_check_latency_seconds` 提供实测 `last`、`moving`；`dae_selection_score_seconds` 单独提供含偏移的选择评分，允许负数。
