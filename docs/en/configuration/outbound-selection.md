# Automatic outbound selection

`min`, `min_avg10`, `min_moving_avg`, `random` and `failover` filter unavailable paths, then prefer **non-degraded paths → higher priority**. If all usable paths are degraded, they remain eligible as fallback.

## Measurements and degradation

`min` uses the last successful probe, `min_avg10` the last ten successful samples, and `min_moving_avg` their EMA (configurable as `min_moving_avg(alpha: 0.18)`). Failures never enter latency statistics; latency is unknown until a successful sample.

Within a degradation/priority tier, latency policies compare the measured statistic plus `add_latency`. Conditional priority uses the measurement before offsets. Negative offsets cannot override degradation or priority; `check_tolerance` only applies within a tier.

A confirmed failure degrades the path. Its first successful test permits degraded fallback and starts `failure_recovery`. Probes repeat at `min(check_interval, 5s)`; an endpoint success lifts degradation. Failure or paused observation restarts an incomplete window. Shared paths reuse probes with group-specific durations. Target errors, cancellation, queue timeout and sleep neither directly penalize a path nor replace successful verification.

`check_interval` controls continuous monitoring of healthy nodes and defaults to `3m`. Recovery temporarily checks about every `5s` with the defaults, including verification at the `30s` window boundary. The window starts at the first recovery success; elapsed time alone never lifts degradation.

## `policy: failover`

```text
group {
    proxy {
        filter: subtag(primary) [priority: 10]
        filter: subtag(backup) [priority: 1]
        policy: failover
        failure_recovery: 30s
        probe_timeout: 3s
        selection_timeout: 15s
        upgrade_interval: 3m
        upgrade_interval_max: 1h
    }
}
```

These are defaults and require an explicit automatic policy. Durations must be positive.

Failover does not maintain periodic latency checks on a healthy current path or its same-tier peers. Real results from manual tests, failure confirmation, shared-group monitoring or recovery verification still trigger selection by degradation, priority and last successful latency plus `add_latency`, respecting `check_tolerance`. A better same-tier peer can replace the current path. Usable recovering same-tier candidates complete their observation windows, then stop continuous checking. Silent failures are discovered on subsequent use.

A real test updating the current path's score also triggers bounded verification of dormant peers with better historical scores and no confirmed outage. Releasing physical resources does not exclude same-tier candidates. If verification finds a candidate no longer better, selection considers the others without enabling periodic standby checks.

Startup and replacement test tiers in order, concurrently within a tier. Equal static priorities and offsets permit first-success selection. Otherwise, selection waits within its deadline only for possible winners. Conditional priority uses its maximum possible value for discovery and its measured value for selection.

`probe_timeout` covers queueing, connection and verification; `selection_timeout` bounds the round. Same-path/network checks coalesce. A successful result triggering reselection, including the recovery endpoint check, supplies the proof directly. Proofs bind path, network capability and Session generation; new failures invalidate them.

Proofs are recorded per destination network: success on one network cannot refresh another network's proof, and historical capability support cannot replace verification. Once a failure invalidates a proof, even the previously selected path needs a new proof for that network before resuming service. If a shared check expires on an earlier caller's shorter budget, a longer-budget caller can retry within its remaining time while retaining the transport. Retries never reset the caller's deadline.

Every replacement candidate must pass connectivity verification for the destination network. Historical latency and health guide ranking; without a reusable successful proof for the round, the candidate is verified again, and failure or timeout moves selection to other candidates. A switch triggered by a successful test reuses its proof and revalidates it at commit; session establishment alone is insufficient. Verification runs in the background while the current path remains usable; otherwise requests wait for a verified replacement within their total selection budget.

Potential improvements receive checks at `upgrade_interval`, backing off exponentially with jitter up to `upgrade_interval_max`. Higher-priority paths return after recovering from degradation. Paths under continuous monitoring or recovery observation supply results for the networks they verify; replacement or independent warm-backup admission still requires separate verification for other networks without valid proofs. Unavailable groups use backoff recovery rounds.

Tiered discovery retains attempted candidates across bounded rounds and continues with unvisited candidates before starting another sweep. Slow failing upper tiers cannot indefinitely starve a lower fallback. New successful proofs can re-admit candidates to selection; requests still share their original total waiting budget.

## Continuous policies and verification

Continuous policies let lower tiers sleep only when the serving tier has another usable peer. A lone usable primary, or loss of its peers, keeps lower-tier candidates monitored until a peer recovers. Peers must support the same destination network; aliases of one physical path do not count as independent backups. Dormant candidates that could enter the active or a higher tier receive discovery checks.

With a usable current path, background verification leaves traffic on it. Only startup and failure elections make requests wait, bounded by one `selection_timeout` budget across restarted elections and both IP families. Elections retain published kernel routing; failed elections apply fallback and `skip_while_noalive`. Other direct traffic keeps its existing kernel bypass conditions.

## Scheduling responsibilities

- **Group scheduler**: owns elections and probe demand per destination network. It rechecks successful results' validity and current ranking before committing; an expired winner does not discard verified runners-up.
- **Shared path worker**: serializes one-shot verification, continuous monitoring and recovery observation, coalescing same-path/network requests. Groups share results but compute their own latency statistics, priorities and recovery durations.
- **Transport lifetime**: combines monitoring, selection, connection and proof demand. Successful proofs retain resources through handoff; new failures or Session generations invalidate old proofs.

## Dormancy and status

Shared paths combine group and traffic demand. Sessions without monitoring, selection, probe or retained-caller/connection demand are released and recreated on demand. Sleep preserves measurements and degradation. Stopping dae checks does not stop protocol heartbeats on sessions still in use.

An accepting pool with missing capacity can replenish even when path verification fails. Successful repair prompts fresh verification; connecting a slot is not a health proof. Increased usable capacity prompts further replenishment; failures or no observable capacity progress back off. A successful connection whose new slot is immediately lost does not clear backoff. Selected paths and retained callers can repair capacity with periodic latency checks paused.

Status Last/Avg10/EMA contain successful latencies. Failed paths show `[degraded]`; the first recovery success starts `[recover 5s/30s verified]`. The numerator is recovery time verified by successful probes, not a live clock: it starts at `0s` and advances only on later successes, so it can remain at `0s` while waiting or probing until timeout. The `30s` window controls when degradation ends, not how long failure confirmation takes.

`STATE` shows health alongside the worker's current action, such as `healthy (verifying connectivity)`, `healthy (recheck in 5.0s)` or `confirming (queued for check slot)`. Recovery observation countdowns use the actual scheduled probe deadline; a failed probe changes health to `fail`. Only a released physical transport shows `dormant`, once, with historical sample age beside latency.

API `selection.tracking` is the group-local role: `selected`, `monitoring` or `standby`. Standby does not mean physical sleep or abandoned recovery: other groups may share monitoring, and unmonitored higher-priority candidates still receive discovery checks. `recovery` reports the shared worker's action and retry time; node `dormant` separately reports physical sleep. `selection` also reports `recovery_elapsed`, `failure_recovery`, effective priority, score and `measured_at`.

`dae_check_latency_seconds` exports measured `last` and `moving` samples. `dae_selection_score_seconds` separately exports the offset-adjusted score, including negative values.
