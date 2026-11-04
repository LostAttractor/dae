# Automatic outbound selection

`min`, `min_avg10`, `min_moving_avg`, `random` and `failover` filter unavailable paths, then prefer **non-degraded paths → higher priority**. If all usable paths are degraded, they remain eligible as fallback.

## Measurements and degradation

`min` uses the last successful probe, `min_avg10` the last ten successful samples, and `min_moving_avg` their EMA (configurable as `min_moving_avg(alpha: 0.18)`). All confirmed modes of a path share the representative probe samples, with each group applying its own statistics settings. Failures never enter latency statistics; latency is unknown until a successful sample.

Within a degradation/priority tier, latency policies compare the measured statistic plus `add_latency`. Conditional priority uses the measurement before offsets. Negative offsets cannot override degradation or priority; `check_tolerance` only applies within a tier.

Upstream errors start failure confirmation, which probes the path once for all concurrent reports. So does a proxied TCP connection whose upstream returns nothing within the probe timeout (8 s) after the caller's first payload: a black-holed path produces no relay error, because its callers give up first. Node carriers over plain TCP also close after 30 s of unacknowledged data, longer than a failed health check, so pools replace black-holed connections; MPTCP carriers rely on keepalive.

A confirmed failure degrades the path. Its first successful test permits degraded fallback and starts `failure_recovery`. Probes repeat at `min(check_interval, 5s)`; an endpoint success lifts degradation. Failure or paused observation restarts an incomplete window. Shared paths reuse probes with group-specific durations. Target errors, cancellation, queue timeout and sleep neither directly penalize a path nor replace successful verification.

A confirmed representative failure marks that mode failing and keeps every capability. Selectors switch to an alive replacement at once, without waiting for the failed node's recovery. A recovery attempt probes every supported mode; the first to answer in representative order becomes the representative, and failing modes receive no traffic until a probe succeeds. Changing the representative does not bypass `failure_recovery`.

Retries share one rule: an attempt to clear a lasting condition waits a quarter of how long the condition has lasted, at least 1 s and at most a cap, with jitter. The condition's end is noticed within about 25% of its duration, while a lasting condition costs about 40 attempts until the wait reaches a `1h` cap after four hours, then one per hour. It applies to a failed path, to discovery of unknown modes on a reachable path and to missing pool capacity, all capped by `check_interval_max`, and to the elections of an unserved network, capped by `upgrade_interval_max`.

A failed path recovers on its own schedule under this rule, counted from the confirmed failure. Session churn, including the path's own reconnect attempts, never shortens the wait. Automatic groups keep their failed candidates monitored; elections and upgrade checks skip them, and a recovered path reports to every group sharing it. Selector groups only monitor their selected or tracked members. Once a mode is confirmed, discovery of the remaining unknown modes counts from the start of its round, which an explicit check, an environment change or a reload restarts.

`check_interval` controls continuous monitoring of healthy nodes and defaults to `3m`. Recovery temporarily checks about every `5s` with the defaults, including verification at the `30s` window boundary. The window starts at the first recovery success; elapsed time alone never lifts degradation.

## Alive paths and switching

A path is alive when its latest representative probe succeeded in the current Session and no failure awaits confirmation. Being alive is the path's own proof of validity: once the current path's failure is confirmed, the group switches to the best alive path at once, without probing it again, and an alive path that outranks the current one also takes over directly. Dormant, reconnecting and confirming paths are not alive. A confirming current path keeps serving; the group switches only after the failure is confirmed.

A path that takes over from a failed one, or an unmonitored path selected for its latency, is verified once. Like being alive, verification uses the representative probe and checks the path, not each network mode. It needs a representative result newer than the observation the switch relied on: a representative probe already running on the path answers it, an idle path is probed at once even while periodic checks are paused, and repeated requests for one path coalesce. A failed verification is an ordinary health failure, and the group moves on to the next alive path. No extra verification follows an initial selection, a switch to a path that has just been probed, or a latency switch between continuously monitored paths, whose monitoring keeps them current.

Elections run only when no path is alive, for example at startup, when the whole group is down, or when every failover standby sleeps. A path that becomes alive during an election, including the first candidate whose test succeeds, takes over at once while the election continues. After that, only a candidate that is better without `check_tolerance` switches again, and the election ends early once no remaining tier can do better.

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

Failover does not maintain periodic latency checks on a healthy current path or its same-tier peers. Real results from manual tests, failure confirmation, shared-group monitoring or recovery verification still trigger selection by degradation, priority and last successful latency plus `add_latency`, respecting `check_tolerance`. A better same-tier peer can replace the current path. Usable recovering same-tier candidates complete their observation periods, then stop continuous checking. Silent failures are discovered on subsequent use.

A real test updating the current path's score also triggers a bounded test of dormant peers with better historical scores and no confirmed outage. Releasing physical resources does not exclude same-tier candidates. If a tested candidate is no longer better, selection considers the others without enabling periodic standby checks.

Standbys are not monitored and stop being alive once their physical session is released. When the current path's failure is confirmed, a path that is still alive (for example monitored by another group or under recovery observation) takes over at once and is verified once; only without an alive path does an election run, and requests wait for its result.

Elections test tiers in order, concurrently within a tier, and the first candidate whose test succeeds takes over. Candidates with other offsets or conditional priorities that could still win are awaited within the deadline and switch again if they do. Conditional priority uses its maximum possible value for discovery and its measured value for selection. Alive candidates are not probed again, and a candidate whose test succeeds is alive.

`probe_timeout` bounds one test of a candidate during an election or upgrade check, covering queueing, connection and verification; `selection_timeout` bounds the election round. Checks for confirmed modes of the same path coalesce into one representative probe. If a shared check expires on an earlier caller's shorter budget, a longer-budget caller can retry within its remaining time; retries never reset the caller's deadline. After a successful test, the transport stays awake until the group commits or discards the result.

Every replacement candidate must have confirmed support for the destination network. Unknown capabilities require actual discovery; success in another mode cannot establish support, and session establishment cannot replace a connectivity test. Historical latency and health guide ranking, and a failed or timed-out test moves selection to other candidates.

Potential improvements receive checks at `upgrade_interval`, backing off exponentially with jitter up to `upgrade_interval_max`. When a takeover lowers the serving tier (a lower-tier or degraded path takes over), unmonitored candidates of a higher tier receive an upgrade check at once; monitored candidates, including failed ones recovering on their own schedule, become alive by themselves once they recover. Higher-priority paths return after recovering from degradation. Paths under continuous monitoring or recovery observation stay alive through their own probes and need no extra checks. Unavailable groups run election rounds under the shared retry rule for candidates that are not recovering; when every candidate is, requests degrade at once instead of waiting for an empty election.

Tiered discovery retains attempted candidates across bounded rounds and continues with unvisited candidates before starting another sweep. Slow failing upper tiers cannot indefinitely starve a lower fallback. Requests share their original total waiting budget across election rounds.

## Continuous policies and verification

Continuous policies let lower tiers sleep only when the serving tier has another alive peer. A lone usable primary, or loss of its peers, keeps lower-tier candidates monitored as hot standbys until a peer recovers. Peers must support the same destination network; aliases of one physical path do not count as independent backups. Dormant candidates that could enter the active or a higher tier receive discovery checks.

With a usable current path, dormant or untested better candidates are tested in the background while traffic stays on it. Requests wait only for an election when no path is alive, bounded by one `selection_timeout` budget and by the request's own deadline, across restarted elections and both IP families. Elections retain published kernel routing; until a group has a path and while no election has failed since, as at startup, the kernel hands its traffic to userspace to wait for the election instead of degrading it. A failed election publishes the group unavailable; waiting and later requests degrade by `no_connectivity_behavior` and apply `skip_while_noalive`, without waiting during backoff. Once the group is served again, the backoff clears and a later failure elects at once. A request whose own context has ended fails instead of degrading. Other direct traffic keeps its existing kernel bypass conditions.

## Scheduling responsibilities

- **Group scheduler**: owns selection, elections and probe demand per destination network. It decides synchronously when a path reports a check result: an alive path takes over at once and is verified when needed. While the current path is usable, a running election or candidate test owns the network's decision; without a usable path, an alive path takes over even during an election. Before committing an election result, it rechecks that the candidate is alive and its current ranking; an expired winner does not discard tested runners-up.
- **Shared path worker**: schedules one-shot tests, post-switch verification, continuous monitoring and recovery observation, coalescing requests for confirmed modes of the same path. Connecting and the representative probe belong to the whole path, so until the path is alive one-shot tests run one at a time, the representative one first; afterwards tests of different modes run concurrently without queueing behind each other, while tests of one mode and other operations run one at a time. Groups share results but compute their own latency statistics, priorities and recovery durations.
- **Transport lifetime**: combines monitoring, selection, connection and check demand. A successful check retains resources until the group commits or discards it; sleep and reconnection advance the Session readiness generation, so the path stops being alive.

## Dormancy and status

Shared paths combine group and traffic demand. Sessions without monitoring, selection, probe or retained-caller/connection demand are released and recreated on demand. Monitoring keeps only a usable path awake: a failed path sleeps between its recovery attempts. Sleep preserves measurements and degradation. Stopping dae checks does not stop protocol heartbeats on sessions still in use.

An accepting pool with missing capacity can replenish even when path verification fails. Successful repair prompts fresh verification; connecting a slot does not replace health verification. Increased usable capacity prompts further replenishment; failures or no observable capacity progress retry under the shared rule, counted from the first failed replenishment. A successful connection whose new slot is immediately lost does not clear backoff. Selected paths and retained callers can repair capacity with periodic latency checks paused.

Status Last/Avg10/EMA contain successful latencies. Failed paths show `[degraded]`; the first recovery success starts `[recover 5s/30s verified]`. The numerator is recovery time verified by successful probes, not a live clock: it starts at `0s` and advances only on later successes, so it can remain at `0s` while waiting or probing until timeout. The `30s` window controls when degradation ends, not how long failure confirmation takes.

`STATE` shows health alongside the worker's current action, such as `healthy (verifying connectivity)`, `healthy (recheck in 5.0s)` or `confirming (queued for check slot)`. Recovery observation countdowns use the actual scheduled probe deadline; a failed probe changes health to `fail`. A failed path shows `unavailable` with its retry time, such as `unavailable (retry #3 in 72.0s)`, also while its transport sleeps. Only a released transport whose latest observation did not fail shows `dormant`, once, with historical sample age beside latency.

API `selection.tracking` is the group-local role: `selected`, `monitoring` or `standby`. Standby does not mean physical sleep or abandoned recovery: other groups may share monitoring, and unmonitored higher-priority candidates still receive discovery checks. `recovery` reports the shared worker's action and retry time; node `dormant` separately reports physical sleep. `selection` also reports `recovery_elapsed`, `failure_recovery`, effective priority, score and `measured_at`.

`dae_check_latency_seconds` exports measured `last` and `moving` samples. `dae_selection_score_seconds` separately exports the offset-adjusted score, including negative values.
