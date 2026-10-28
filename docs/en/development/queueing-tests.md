# Queueing goals and validation

Queueing work aims to reduce forwarding cost and avoidable waiting under the
same configuration. A single global queue, one algorithm for every protocol,
or an absolute end-to-end latency bound is not the goal.

## Constraints and objectives

The hard constraints are explicit buffer ownership, bounded resource admission,
correct cancellation and release, ordered reliable-stream framing, and accurate
loss accounting. A rejected datagram must not invalidate a healthy shared
connection. Bytes already committed to a reliable stream cannot be selectively
removed; cleanup is bounded, not an unconditional delivery guarantee.

Separate these from performance objectives:

| Situation | Observe | Interpretation |
| --- | --- | --- |
| Low offered load | Process CPU, CPU per probe, latency distribution, resident memory | Detect fixed and per-packet cost; CPU/GB is misleading for sparse small packets |
| Sustained congestion | Useful throughput, CPU/GB, interactive latency, loss, queue trend | Keep avoidable backlog short without starving the carrier |
| Overload or failure | Resource ceilings, progress by unrelated ready sources, rejection, cancellation and recovery | Do not require normal throughput or an unconditional latency ceiling |
| Mechanism diagnosis | Controlled changes to batches, a single carrier or synthetic writer cost | Explain a mechanism; do not treat the fixture as production CPU efficiency |

Prefer the fewest queueing states and feedback mechanisms that satisfy the
constraints and provide the required isolation. Do not add adaptive controls
solely to improve a benchmark ratio.

Declare screening thresholds for the scenario before measuring. For example,
97% of baseline throughput and 105% of baseline CPU/GB can flag regressions in
comparable steady bulk workloads, but are not universal acceptance gates.
Evaluate CPU changes with absolute CPU time, available processing capacity,
throughput and latency benefits, and implementation complexity. A threshold
crossing calls for that assessment, not automatic acceptance or rejection;
paired variation across a threshold remains inconclusive.
There is no universal 120 ms game-p99 acceptance rule. Evaluate latency together
with loss, missing probes, sample count and maximum delay; dropping slow probes
must not manufacture an apparent improvement.

A small congestion window or a stalled carrier does not prove that all observed
waiting is unavoidable. Attribute the extra delay before blaming the transport.
Conversely, normally outstanding bytes awaiting ACKs are not automatically
bufferbloat: reducing the bandwidth-delay product can reduce throughput.

## Small matched comparisons

Use the same host and CPU affinity for both sides, with the same Go version,
tags, linker settings, dependencies and test fixture. Do not replace a binary
during a matrix run. The default matrix runs `normal` (game probes only) and
`saturated` (game plus four bulk streams), twice per binary, in alternating
AB/BA order:

```sh
SUDO="flock $HOME/.cache/dae-root-tests.lock sudo -n" \
  OUT=/tmp/queue-comparison scripts/tests/queueing/matrix.sh \
  /tmp/before.test,/tmp/after.test 2 normal saturated
```

The default topology is a local fixture: 40 Mbit/s CAKE egress, 90 ms return-path
netem, and a Shadowsocks 2022 / smux chain. The CAKE interval parameter is not the
measured carrier RTT; neither it nor the fixture's netem delay establishes a
real node's RTT. Association setup is bypassed by this fixture and needs its own
lifecycle tests. See the [detailed fixture guide](../../zh/development/testing-and-performance.md).

The smux test server passes each complete frame to its carrier in one write,
without waiting to batch multiple frames. Splitting a frame header and payload
into separate carrier writes can create extra encrypted records, reads and
wakeups at the client. Carrier packetization is part of the fixture, not a
universal property of real servers; compare packetization variants explicitly
when attributing small-packet CPU costs.

The default comparison scenarios disable 10 ms socket inspection with the
test-only `QEXP_SOCKET_SAMPLES=false`. This avoids charging a variant for more
observation syscalls merely because it has more carriers. Diagnostic scenarios
retain socket sampling unless explicitly disabled. Normalized CPU fields are
omitted when socket sampling, synthetic writer spin or the LAN-side QUIC client
is active. Pure-game runs expose `cpu_us_per_game_packet` using the window's
offered probes; it must be read with delivery and loss counts.

The client process also generates traffic and records probe replies. Its CPU
is a comparative fixture metric, not an isolated daemon measurement. Delivery
patterns can change generator and recorder wakeups; use stack attribution or
references providing the same isolation before attributing a mixed-load CPU
delta entirely to queue scheduling.

## Report validity

Reports include resolved `conditions`: topology, workload, carrier limit,
server frame packetization,
writer delay, sampling mode, measurement window and runtime platform. The
summarizer excludes incomplete measurement intervals, late samples, missing required loss
accounting and unaccounted losses from performance aggregates. It does not pair
runs with missing or different conditions. Invalid counts and worst validity
checks remain visible; exclusions are explained on stderr. Invalid, incompatible
or missing pairs produce a nonzero exit status; this validates the measurement,
not the performance result.

The matrix records build settings and one fingerprint per binary under
`OUT/artifacts`, and refuses differing Go versions or build settings before
starting experiments. Source revisions may differ. Fingerprints establish
artifact identity, not correctness or full comparability; verify source and
fixture differences separately. Repetitions are paired, not compared across
unrelated historical runs. A two-pair result is a screening result, not a
confidence interval or automatic approval.

Use explicit diagnostic scenarios only after a matched comparison identifies
an issue. Do not repeatedly run the entire diagnostic matrix or change
congestion control, socket settings or loss policy just to cross a threshold.
