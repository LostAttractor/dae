# Automatic outbound selection

`min` uses the last successful probe, `min_avg10` the last ten successful samples, and `min_moving_avg` their EMA (configurable as `min_moving_avg(alpha: 0.18)`). Failures never enter latency statistics; latency is unknown until a successful sample.

Within a priority tier, latency policies compare the measured statistic plus `add_latency`. Conditional priority uses the measurement before offsets. `check_tolerance` only applies within a tier.

`dae_check_latency_seconds` exports measured `last` and `moving` samples. `dae_selection_score_seconds` separately exports the offset-adjusted score, including negative values.
