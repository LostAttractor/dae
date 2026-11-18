# Contribute

If you want to contribute to a project and make it better, your help is very welcome. Contributing is also a great way to learn more about social coding on GitHub, new technologies and their ecosystems and how to make constructive, helpful bug reports, feature requests and the noblest of all contributions: a good, clean pull request.

## Bug Reports and Feature Requests

If you have found a `bug` or have a `feature request`, please use the search first in case a similar issue already exists. If not, please create an [issue](https://github.com/LostAttractor/dae/issues/new/choose) in this repository

## Code

If you would like to fix a bug or implement a feature, please `fork` the repository and `create a Pull Request`.

Before you start any Pull Request, `it is recommended that you create an issue` to discuss first if you have any doubts about requirement or implementation. That way you can be sure that the maintainer(s) agree on what to change and how, and you can hopefully get a quick merge afterwards.

`Pull Requests` can only be merged once all status checks are green.

Core, CLI, outbound protocols, the parser and first-party plugins share the root
Go module and release version. Include contract changes and their consumers in
the same pull request. Copy `plugins.cfg.example` to a local `plugins.cfg` and
uncomment the optional plugin entries to test the full selection with `make test`.
Repeat with `SURGE_RUNTIME=nodejs` for the Node backend.
`make client-test` checks lightweight client dependencies. See the
[build guide](../user-guide/build-by-yourself.md) for parser generation,
third-party forks and external plugin workspaces.

For documentation changes, run `pnpm install --frozen-lockfile`,
`pnpm run test-doc-tools`, `pnpm run markdown-lint` and
`pnpm run check-broken-link` from the repository root. For frontend changes,
run `make -C web test` with Chromium installed. Both use the root pnpm lockfile;
commit manifest and lockfile changes together when changing dependencies.

For DNS registry tests and direct activity benchmarks, see the [testing and
performance guide (Chinese)](../../zh/development/testing-and-performance.md).

Queueing changes use the [scenario-specific validation goals](queueing-tests.md),
including matched build conditions and loss-aware latency interpretation.

## Pinned kernel state

Persistent state includes `tcp_flow_map` (LRU hash, 40-byte key and 24-byte value)
and its atomic gate array (4-byte key, 8-byte value). `socket_owner_map` uses socket-local storage with a 4-byte
key and 20-byte value; `daemon_identity_map` and `fallback_sequence_map` each use
a 4-byte key and 8-byte value.
The device-policy outer/inner maps retain device epochs. Ordinary restart reuses compatible
canonical pins; replacing an incompatible flow map drops its connections' marks and
fallback constraints, not the connections.
Reload within a process shares the Runtime's maps.

Pinned bytes and meanings are an explicit contract. TCP flow properties store
`route_epoch`, `mark`, `fallback`, and `syn_seq` at offsets 0, 8, 12, and 16.
The u32 at offset 20 is `explicit_direct`; `routing_result` uses the byte at
offset 31 for the same evidence. Their sizes remain 24 and 40 bytes. Zero means
unknown, so an old zero-padding value cannot prove direct routing in `STOPPING`.
Fallback zero is not tied to a revocable generation, but does not prove explicit
direct routing; one is always invalid, and other values name unique group grants.
There is no special `PERMANENT` token. The pinned issuance counter never reuses tokens. Socket owner values keep `pid` at offset 0 and
the 16-byte `pname` at 4. Metadata comparisons cannot detect same-size semantic
changes; `TestPinnedMapABI` and fixed-byte fixtures independently check the
contract. A capacity mismatch replaces only the corresponding map.

`TestRemoveIncompatiblePinnedMaps` checks selective replacement and retained IDs
and contents. `TestPinnedTCPFlowEncoding` checks direct marks and token boundaries.
`TestPersistentKernelLifecycle` creates private network/mount namespaces, bpffs,
and `/run`, and starts only its own helper processes. It verifies one real TCP
connection across SIGKILL, a restart that never goes online, and takeover, together
with normal-stop cleanup, including map pins of earlier versions, identity
revocation, epoch recovery, fresh UDP routing after process exit, private timer
map replacement, and cleanup failure boundaries. Native NAT tests use disposable namespaces
and minimal nftables rules for IPv4/IPv6 local sockets, local DNAT, and LAN
forwarding; concurrent handshakes must not mix a new SYN's policy with a delayed
SYN-ACK. Never access a running daemon's pins or kill unrelated processes.
Keeping kernel state does not preserve userspace relay sockets; process-local
fallback generations can still end on cold restart.

## Table capacity snapshots

Status samples hash/LRU map occupancy with the kernel's existing element counters.
The optional BPF iterator samples counters only for map IDs selected by the current control plane;
it does not walk flow entries, refresh LRU entries, or count packets. Per-CPU sums
are sampled rather than transactional during concurrent churn. Array rows report
compiled instruction or LPM-map slots, not the array's preallocated cells.

Userspace UDP rows read the existing source, packet-resource, and reply-socket
admission budgets once per shared resource. Opening and closing reservations stay
charged until their admission owner releases them. Occupied entries are not active
connection counts. A failed read is unavailable, never an empty table. Tests use
private small maps and pool fixtures; no production table contents are inspected.

## Private replacement state and blocking guards

Process replacement is a restart with failure protection, not a globally atomic
or lossless handoff. Before Block, failures preserve the old service. After Block,
closing old connections is irreversible; failures retain fail-closed protection
until successful recovery. Incremental installation and retirement across hooks
are protected intermediate states, not one global transaction.

Only process replacement and guard recovery create private business maps without
adopting the predecessor's business pins. Successful commit explicitly publishes
the successor's canonical pins; normal operation remains persistent, ordinary
restart reuses compatible pins, and configuration reload shares Runtime maps.
TCP/UDP userspace relay sockets, fallback leases and private connection state do
not migrate across exec. Links for shared network objects are handed over through
FDs. Link roles, the fixed topology and the managed interface set remain handoff
contracts. See the [process replacement design (Chinese)](../../zh/design/process-replacement.md).

Each guard bundle under `/sys/fs/bpf/dae/guards/<link-id>/` holds its ingress link,
`udp_conn_state_map`, `udp_routing_cache_map`, that generation's socket-owner
writer links, exit hook and `daemon_identity_map`. Only UDP has timer maps. Kernel
timers need a map FD or map pin; a link→program→map reference alone does not keep
expiry collection running. Old canonical and guard references must both be
released. Reusing a pin name must not update an old identity writer to the new
program. Guard maps are not adopted as successor business state. Recovery verifies
coverage of every old capture hook before releasing guards.

TCP setup uses a short-lived handoff followed by the real accepted socket.
SOCKHASH is optional acceleration; full or failed registration falls back to proxy
network-namespace socket lookup. The 24-byte LRU `tcp_flow_map` stores only native
properties, not a proxy admission ledger or FIN/ACK state machine. There is no TCP
timer takeover. Successful replacement follows ordinary restart semantics:
unknown non-SYN packets are native in `ONLINE`, not permanently rejected.

`TestTCPProxyTupleKeepsAcceptedSocket` and `TestTCPSocketIndexLifecycle` check real
accepted-socket ownership and the optional SOCKHASH index lifecycle;
`TestTCPFlowEvictionKeepsConnection` checks that LRU property eviction does not
close a real connection. `TestStoppingEntryAndExit` and
`TestStoppingUDPAndFragments` distinguish `STOPPING` rejection of captured or
uncertain traffic from `ONLINE` native behavior, including unknown non-SYN packets
and replies to newly observed inbound TCP connections. Existing explicit-direct
traffic may continue through a single old guard while its evidence remains valid;
non-first fragments do not. This is not a cross-generation continuity guarantee:
private old/new maps do not share direct evidence, so overlapping guards may pause
direct traffic, and a later failure can extend the pause until successful recovery.
Replacement tests must allow that pause while still rejecting captured or uncertain
traffic; do not require uninterrupted direct traffic.

`TestReplacementGuardBundleKernel` checks bundle references, repeated pin identity,
partial-failure rollback and cleanup order. `TestGuardTimerMapReferences` compares
actual UDP GC after closing map FDs with only program references versus additional
map pins. `TestReplacementGuardsKernel` and
`TestFailedRecoveryDoesNotExpandGuardsKernel` check blocking after process-owned
FDs close and prevent failed recovery from expanding the required hook set.
`TestFailedRecoveryPrunesUDPTimerPinsKernel` checks that failed candidates release
unused timer pins while preserving references from attached guards, including
partially cleaned bundles. `TestFailedRecoveryTimerPinsKernel` runs two separate
daemon processes whose live plugin constructors fail; neither may leave unused
runtime timer pins or disturb the existing DROP guard. Run each in fresh private
PID/network/mount namespaces with private `/run` and bpffs.
`TestUDPRepliesReleaseRetiredTimerPrograms` checks UDP timer callback retirement
without introducing TCP timer state. Use isolated maps, PID/network/mount namespaces
and private bpffs; never use a running daemon's pins.

## UDP conntrack and replacement tests

UDP retains `udp_conn_state_map`, `udp_inbound_pending_map`, bindings, routing
caches and their timer lifecycle. Host-namespace conntrack (CT) supplies the
direction evidence needed to restore inbound replies in a new private generation:
only `CT_ORIGINAL` creates inbound pending state and only `CT_REPLY` restores
inbound replies. LAN ingress queries an existing record in the default zone
using the packet's forward tuple; local WAN egress reads attached CT, including
NAT-translated packets. Missing or expired CT and NOTRACK do not prove direct or inbound
traffic. `udp_routing_cache_map` and `udp_bindings_map` retain routing-cache and
proxy-association responsibilities, not direction evidence. Genuine inbound
replies across process replacement depend on still-valid system CT; without it,
session continuity is not guaranteed.

`DAE_REPLY_MARK` identifies a synthetic relay reply, not the client's connection
direction. WAN synthetic UDP replies require the correct existing host CT REPLY
direction before reinjection. A late reply with missing or mismatched CT is
dropped rather than allowed to create a reverse connection. LAN synthetic replies
go directly to LAN egress and do not require host CT for ordinary LAN relay.

Missing required CT support rejects startup or replacement preparation. The
preflight exchanges real IPv4/IPv6 loopback UDP packets in the serving host
namespace, then checks ORIGINAL/REPLY with an unattached BPF probe. This tests
lookup/release, options ABI, verifier support and actual namespace tracking,
not just module presence. Production preflight does not attach loopback TC,
change firewall rules or flush CT. Errors distinguish probe loading, UDP
exchange and direction-query failures by family and stage. A successful loopback
check does not guarantee interface-specific NOTRACK, custom zones or future
administrator changes. Business lookup misses still follow routing admission;
they do not terminate the service or grant an inbound exemption.

- `TestHostConntrackIntegration` uses private network namespaces to cover enabled
  tracking, no tracking, NOTRACK and a nondefault zone. Startup fixtures enable CT
  explicitly in their own namespace rather than bypassing the production check.
- In `control/kern/tests`, `TestUDPForwardConntrackReplacement` uses real CT and
  isolated router/LAN/WAN endpoints. It covers IPv4/IPv6, outbound reply-first and
  client-first ordering with and without SNAT, and the first local inbound reply
  after replacement with and without DNAT. Other destinations on the same socket
  must still follow the new routing rules.
- `TestUDPInboundStateBehindRedirect` covers inbound reply direction after
  REDIRECT. `TestUDPReplacementWithoutConntrack` rejects inferred inbound
  exemptions without CT; `TestUDPReplyMarkerWithoutConntrack` checks that a reply
  marker is not direction evidence. `TestUDPNotrackDoesNotExemptReplyAfterReplacement`
  checks that NOTRACK cannot exempt a reply after replacement.
- `TestUDPRelayDoesNotCreateInboundConntrack` uses production Netkit/veth paths
  for LAN/WAN and IPv4/IPv6. It removes only the fixture flow's host CT, sends a
  synthetic reply, and checks that WAN drops it, LAN direct delivery still works,
  no reverse CT appears, and the next client packet is still captured. Run with
  `DAE_TEST_ISOLATED=1` in isolated PID/network/mount namespaces with private bpffs,
  never in a serving namespace.

The end-to-end `scripts/test-process-replacement.py` fixture also requires root,
Python 3.12+, iproute2, nftables and `util-linux`. It adds a minimal nft CT state
reference only in its private host namespace; production does not enable
tracking by changing the host firewall. It checks a single resident business
process, stable PID/starttime, actual `/proc/<pid>/exe` identity and a new API
`StartedAt`/startup log for each exec, including forced same-ELF replacement.
Preflight rejection must leave the old API and traffic available. Hold a controlled,
uncached subscription download before Block and require the old API and captured
traffic to continue, with shared exports unchanged. After input preparation,
change or remove the configuration/includes and local resource files and stop the
subscription server: strict exec replay must consume the accepted inputs without
extra requests or rediscovering files. Separately verify Block with guards present,
captured DNS denied without direct leakage, and exports unchanged until commit.
During Block, API requests may receive 503, time out or disconnect: retained
listener FDs do not keep Go HTTP servers alive. Invalid settings and ports occupied by another process
are post-Block failures that retain guards, fixed objects and existing exports;
normal cold startup recovers after repair, but the old operation fails. The fixture
also checks idle TCP resets, listener reuse/port changes, stable FDs and repeated
SIGKILL/cold recovery.

After building, add `--wan` to exercise daemon identity through a real private WAN:

```sh
sudo python3 -I scripts/test-process-replacement.py "$PWD/dae" --wan
```

This mode creates a private `wan0` veth and an `upstream` network namespace with
an HTTP subscription server, rather than bypassing capture through loopback. A
random URL, an initially absent subscription cache, and matching URL/body in the
validated response establish that target prefetch obtained uncached data before
Block. Stop the server after preparation and require exec replay to make no extra
request. An ordinary other PID must remain denied by the explicit block rule for
that same destination while running, during prefetch, during Block and after
takeover; daemon identity must not exempt other processes. Both modes
use only isolated local networks, not the Internet. See the
[test procedures (Chinese)](../../zh/development/testing-and-performance.md#进程热替换).

## Same-PID exec tests

Run the unprivileged protocol and lifecycle tests first:

```sh
go test -race ./internal/daemon ./internal/handoff
```

`internal/handoff` uses its own test ELF for `TestSelfExec`, covering different
images and forced same-image exec, stable PID/starttime, fresh package initialization
and heap, preserved environment/arguments, child cleanup and stable FD counts.
`TestExecFailure` checks exec errors and the FD whitelist; `TestSealedState` and
`TestReadStateRejectsInvalidInput` check sealed memfd validation.
`TestSignalsStopDrainsQueuedSIGTERM` checks the stop-signal barrier;
`TestDrainChildren` and `TestChildrenAcrossThreads` check descendant cleanup and
discovery across threads. In daemon, `TestReadReplacementRejectsInvalidState` and
`TestStartupRejectsInvalidInheritedDescriptors` reject invalid internal entry;
`TestStopReplacementCandidate` requires PID-exemption revocation before reaping.
The kernel `TestReplacementPIDRevokedOnExit` checks that daemon or candidate exit
also clears the temporary exemption without weakening `STOPPING`; unrelated exits
do not revoke it.

On a systemd test host, test the real exec primitive without BPF:

```sh
go test -c -o /tmp/dae-handoff.test ./internal/handoff
sudo python3 -I scripts/test-exec-systemd.py /tmp/dae-handoff.test
```

The fixture creates uniquely named transient `Type=simple` and `Type=notify`
units with `NotifyAccess=main`, `Restart=no` and `KillMode=control-group`. It checks
stable MainPID/starttime across real ELF changes and forced same-ELF generations,
preserved environment/arguments, child reaping, stable FDs, RELOADING → READY,
normal stop and `Result=signal` after SIGKILL. Its RSS and idle CPU output measure
only the minimal fixture, not daemon forwarding. Cleanup stops only its own units.

## Replacement persistence and measurements

Non-root input-boundary regressions include
`TestPreparedInputsRebuildWithoutLiveSources` (configuration, local subscriptions,
successful/failed remote subscriptions and modules after source deletion and
server shutdown, unchanged accepted nodes and three requests, no live plugin),
`TestUserspacePreparationCompilesStaticPlanBeforeInstances` (static routing without
business BPF or live instances), and the `TestInputs*` codec/group tests. Pluginhost
checks factory order, context ownership, missing declarations and resource-error
rollback. Config, assets, geodata, routing and local-subscription tests cover frozen
selection, ordinary security checks, missing replay entries and capture limits.
The kernel-backed `TestPreparationConnectivityProjectsOriginalFallbackLease`
checks that binding projects the retained lease rather than issuing a new policy
identity during userspace preparation. `TestHostIdentityPrecedesBusinessMaps`
also needs root: it checks that only socket-owner hooks/map exist initially, a real
socket already has its kernel TGID, and subsequent business BPF reuses that map
while temporary FDs are released.

The daemon runs a short-lived target ELF preflight with its own effective run
arguments, environment and working directory, not the reload CLI's environment.
Preflight uses the target parser, plugin `Preflight` and kernel checks, then
constructs a userspace control plane without business BPF. It reads configuration
and include/glob selections, subscriptions, modules/dependencies, geodata and
complete static plugin plans before Block. It does not read settings/Registry,
construct live plugin instances, execute `Warm` or plugin workers, construct a full
Runtime or publish client sets. The old dataplane and API remain available during
prefetch; new configuration operations return 409. The parent revokes the temporary
PID exemption before `Wait`. After preflight cleanup, the
daemon freezes links, collects inherited FDs, and encodes and seals the handoff
description before pausing plane requests and entering Block. The drain can be canceled
without reinstalling the handler. Management reads/writes receive 503 during the drain;
operation queries may time out or disconnect while only listener FDs survive exec.
The API barrier freezes daemon writers, not external file editors.

The internal handoff protocol version is 6. Same-PID exec retains only whitelisted
FDs and carries the original process name in the sealed description. The handoff description remains a sealed memfd bounded to 64 KiB; operation
inputs use a separate memfd created by the parent, written and sealed by the
target through `ExtraFiles`. A single input or complete resource group is limited
to 128 MiB; the whole archive, including its header, index, payload and digest, is
limited to 512 MiB. Recovery validates seals, size, protocol, PID,
the original deadline, FD roles/uniqueness and lock/namespace/link identities, then
restores CLOEXEC before plugins can inherit FDs. There is no resident supervisor,
predecessor-pidfd wait, adopted business worker or commit-authorization message.
Before initialization, startup restores the process leader's `/proc/self/comm`;
FD-based exec must not change the identity used by `pname()` routing.
`TestRestoredProcessNameRoutesInternalRequests` checks restoration from a non-leader
Go thread and fixed-name rules for internal DNS and resource requests. The exec
fixture checks the name and lock inode across replacements and retries concurrent
`dae run` after replacement and crash recovery.
Old heap/goroutines disappear, so Runtime close, flush and descendant reaping must
finish before exec. Stop signals and the remaining transaction deadline are checked
at that boundary; the deadline does not reset. Permanently stuck ELF loading or
package initialization still requires an external manager, not a resident watchdog.

When resuming from validated sealed exec state, `Run` skips repeating
`CheckKernelFeatures` already passed by the target ELF, but still runs plugin
Configure/Preflight on the replayed configuration and loads/verifies business BPF;
cold startup and restarts after failure retain full checks, settings/Registry
are read only after the old writer closes, and no kernel-capability cache structure or configuration
is introduced.

Input replay is strict: configuration bytes and include/glob selection, asset
locations and contents, and complete accepted resource-cache groups are frozen.
Groups retain successful reads, failures, validated fallback and skipped-subscription
decisions. Missing or inconsistent entries, corrupt archives and input limits are
fatal; `ErrInputRecording`/`ErrInputReplay` must not trigger live fallback, compatibility
fallback or optional-resource skip. Only initialization readers carry this context;
runtime services and later reloads do not. No parsed `Config`/`Value`, live plane,
settings or Registry objects are serialized.

After exec, startup calls `settings.Open` once for outbound selection, private
routing and later exports. It reconstructs userspace objects from the frozen raw
inputs, then binds business BPF and builds live services. Downloads and static
validation precede Block, but invalid final settings, ports occupied by another process, plugin
construction, `Warm`, business BPF loading and publication may still fail after
old-service retirement. Replay failure also retains guards, without fetching new
inputs. The new runtime locally
updates the socket lookup, peer DNS egress and both ingress links, then attaches new host TCX links after old guards.
Temporary old WAN socket-owner hooks remain separate from new `pidLinks` until old
guards retire. Their `socket_owner_map` storage stays generation-local; formal
identity is registered in `daemon_identity_map`, including re-registration with
old guards on a fresh recovery start. The exit hook unregisters the actual exiting
identity without overwriting `STOPPING`; `replacement_pid_map` is a separate,
temporary preflight exemption. `KernelProcessID`
uses a temporary map-free BPF probe to obtain the kernel TGID for `PARAM` and the
preflight hello, matching socket owners even inside a PID namespace without an
extra socket-hot-path lookup.

Logical routing identity is separate from the actual exempt TGID: the helper uses
the old daemon's logical PID/pname for resource-request routing, while its actual
kernel TGID receives the temporary exemption. Selector choices during prefetch are
only old in-memory hints; final settings remain authoritative after exec. Formal
Runtime startup establishes its namespace and interface view before compiling
userspace routing, and installs minimal host socket-owner hooks before persistent
proxy sockets. It loads business BPF only after userspace preparation. This keeps
API exemptions and interface rules consistent with the installed host topology;
the minimal hooks do not allocate business routing, traffic, timer or listener maps. Unbound
connectivity updates retain their original fallback lease; token issuance waits
until kernel projection after binding.

DomainRegistry first restores during `PrepareKernel`, after old Runtime close/exec
and before new host entries are installed. The old writer closes and completes its final flush before the
new writer reads the final baseline/journal and enables persistence, preserving
single-writer ownership without merging a warmup snapshot or forcing a baseline
rebuild. `CommitReplacement` prepares client exports, installs the new downstream
and host programs, applies the exports, then starts plugin workers through `Host.Start`, enables Registry persistence, validates
complete hook coverage, publishes its canonical pins, incrementally releases old
guards and enters `ONLINE`. `ONLINE` is this runtime's dataplane activation point,
not an atomic publication of every hook and shared export. Its own guard bundles
and `privatePins`/`preparing` interface freeze remain while `ConfirmReady` validates
the attachments and sends READY within the original deadline. Successful notification
grants canonical-pin cleanup ownership and clears `replacement_pending`. This bpffs
marker is created before any canonical pin is replaced, even without a host guard. Fixed network
objects and the Unix API socket also remain borrowed until final readiness. READY
is a readiness notification, not a globally atomic commit receipt: a late READY
failure or cancellation can still re-block and terminate the successor. This is
failure handling after activation, not recovery of the old process; READY failures
are not ignored.

No shared exports change during preflight. Pre-Block failures keep the old service
and resume admission to the original API handlers; post-Block failures retain applied sets and guards
while cleaning temporary export backups, without resuming the old business or
rolling back published sets. After commit, redundant guard-bundle cleanup and
unreferenced old UDP timer-pin cleanup failures only log warnings, as does export
backup cleanup after successful takeover. State/topology validation failures and
errors retiring old guards before commit completes remain fatal. Ordinary
configuration reload keeps its export rollback behavior. Full initialization is
part of the interruption, with no lossless or fixed-duration guarantee. See
[DNS persistence](../configuration/dns.md#persistence-and-diagnostics).

`TestReplacementRestoresFinalRegistry` checks the predecessor's final append,
compaction and activity renewals, current-rule projection, and normal journal
appends without rebuilding a healthy baseline.
`TestReplacementRegistryCloseBeforePersistence` checks that closing before
restore or before persistence is enabled does not write back, including complete
`.tmp` and legacy files. `TestReplacementRegistryProjectionFailureKeepsStaged`
keeps incomplete projection from starting plugins, enabling persistence or
releasing staging. `TestReplacementRegistryRejectsClosedPlane` checks the
shutdown barrier. `TestReplacementOpensFinalSettings` checks that the candidate's
first open sees the predecessor's final selector, MITM and membership preferences,
which subsequent writes must preserve. `TestReplacementRejectsInvalidInitialSettings`
rejects corrupt settings at that first open. These tests use temporary directories
and map callbacks:

```sh
go test -race -tags=netgo,osusergo,trace ./control \
  -run '^TestReplacement(OpensFinalSettings|RejectsInvalidInitialSettings|RestoresFinalRegistry|RegistryCloseBeforePersistence|RegistryProjectionFailureKeepsStaged|RegistryRejectsClosedPlane)$' -count=1
```

`TestReplacementFailureAfterBlockKernel` and
`TestReplacementCloseFailureAfterBlockKernel` run the target test ELF's real
parser/plugin Preflight and userspace input preparation; live plugin construction,
`Warm` and workers must remain deferred.
They check available old API/new-operation 409 during preflight, rejection and
cancellation without retiring the old service or releasing its lock, and 503 only
at final API drain. Invalid settings do not fail preflight. Cancellation or shared
plugin state close errors after Block must prevent exec and new exports, retaining
old sets, fixed objects and pinned guards.

`TestReplacementReadinessFailureKernel` and
`TestReplacementReadinessCanceledKernel` cover failures after datapath publication,
while fixed objects remain borrowed: a failed READY notification or canceled startup
must re-block before shutdown, retain fixed objects and keep published sets.
These checks cover failure handling after `ONLINE`, not rollback to the old process
or an atomic commit acknowledged by READY. Configuration operations remain blocked
until the replacement operation completes.
`TestReplacementReadinessSuccessKernel` receives READY over a local Unix datagram
socket and checks that only successful readiness ends recovery protection and
transfers deletion ownership. `TestReplacementClaimKeepsInterfaceFreezeUntilReady`
checks that failed state/topology validation preserves `privatePins` and the
interface freeze, and only a successful claim releases them. Redundant bundle
cleanup failures on an already committed runtime must warn rather than fail the
claim; tests must keep these separate from fatal validation or old-guard retirement
errors. Normal shutdown must then remove the adopted network objects, canonical
pins and Unix socket.

`TestStartupStopBeforeRunKernel` blocks in I/O after `OpenStartup` but before
`Run`, modeling configuration reads that do not accept context cancellation.
SIGTERM must trigger the 15-second shutdown watchdog's forced exit. Startup
installs the only `watchShutdown` before configuration I/O and owns cancellation
and the recovery deadline. Run shares this lifecycle without handing over a
watchdog or resetting an already-started stop deadline. This test requires root,
`DAE_TEST_ISOLATED=1`, isolated PID/network/mount namespaces and private `/run`.
It does not extend daemon watchdog protection to ELF loading or package initialization.

`TestStartupLifecycleBudget` uses virtual time to check completed preparation,
recovery expiry before Run, an earlier stop signal and repeated shutdown requests.
Completing preparation must not cancel the business context; repeated shutdown
requests must not extend the grace period. `TestStartupJoinsExpiredPreparation`
checks that stopping the recovery timer joins an already-running cancellation
callback, preventing expiry from arriving after readiness. These lifecycle tests
do not require root.

`TestReplacementSnapshotFileOwnership` uses local files without root to check
one-time FD transfer, repeated snapshot release and closing only untransferred FDs.

`TestReplacementRetainsSocketIdentityHooksKernel` checks temporary old WAN identity
hooks across Runtime close, private old/new socket storage, kernel TGID agreement
with real socket owners, rejected swapped hook FDs without leaks, and guard/hook
retention on cancellation or topology change. It also runs real `PrepareKernel`
to check that final Registry restoration happens once, before attachment installation
and without enabling persistence early. Exported FDs
transferred by `TakeFiles` must survive snapshot release and old Runtime close,
and remain importable by the new Runtime; the snapshot closes only untransferred
FDs. Successful Commit retires only the old hooks. `TestReplacementCommitCancellationWithoutHost` checks
cancellation without a MITM host; `TestReplacementRequiresPreparationBeforeCommit`
rejects an unprepared or unpublished replacement.

`TestReplacementCommitExportsFailureKernel/prepare` rejects an incompatible nft
set before consuming pending attachments or adding guards, leaving old exports
unchanged. Its `after-apply` case fails `Host.Start` after
real ipset/nft publication; `partial-apply` uses nft capacity to fail publication
partway through. Both keep applied sets and staged/guard protection while removing
temporary backups. Run each kernel test in a fresh test process with root,
`DAE_TEST_ISOLATED=1`, isolated PID/network/mount namespaces, private `/run` and bpffs.

Surge's `TestRuntimePersistentStoreIsLazy` checks construction, `Warm`, a script
that does not access the store, and `Close` without loading contents or creating
store directories, JSON or `.lock`. `TestRuntimePersistentStoreSharedBeforeFirstAccess`
checks sharing before access and closing one runtime while the other remains
usable. Store tests cover external atomic replacement before the first read/write,
invalid JSON/FIFO failure and repair, cross-process merging, flock and gate deadlines:

```sh
CGO_ENABLED=1 go test -race ./plugins/surge \
  -run '^(TestRuntimeStore|TestRuntimePersistentStore|TestRuntimeRetiredStoreIsReleased|TestConfiguredStore)' -count=1
```

Run for both backends; add `-tags=surge_nodejs` for Node, retaining `CGO_ENABLED=1`
for race testing. Node worker tests need delegated cgroup v2 memory; use the
[temporary-unit procedure (Chinese)](../../zh/development/testing-and-performance.md)
rather than changing a running service. Store construction may still perform path
metadata I/O; it does not read the store contents. Actual read/write calls retain
refresh checks, cross-process write locking and atomic save behavior; invalid files
fail at access without being overwritten and can be retried after repair. This
contract does not defer all caches or certificates.

Distinguish the first full `Restore` from the complete cutover stage. Restore
includes validation, journal replay, expiry collection, rule matching and BPF
projection, not just file reads. The `Replacement inputs prepared` log's `duration`
runs from the parent's prefetch start through receipt and validation of the sealed
archive, exemption revocation and `Wait`; `bytes` reports the archive size. It
includes target startup, probes, reads/downloads, validation, userspace preparation,
sealing and cleanup, not just disk/network I/O or local construction. The
`Replacement datapath ready` log's `cutover` field measures final description
sealing through dataplane readiness, including API draining, Block, old shutdown
and initialization after exec. It is not pure traffic-blocking time. The fixture
reports these as `preparation_ms` and `cutover_ms`. Report
continuous DNS inter-arrival gaps separately: they also include scheduling,
client timeouts and connection setup, not pure blocking time or a zero-loss
guarantee. A suite-wide gap spanning failures and cold recovery is not a successful
handoff's duration.

For memory, sum `/proc/<pid>/smaps_rollup` PSS and `Private_Clean + Private_Dirty`
over the entire daemon process tree, including temporary preflight and plugin
children. Record stable states and the sampled replacement peak; the end-to-end
fixture samples every 20 ms. Report the interval, process count, configuration,
resource-cache state and toolchain, since shorter transients may be missed.
Main-PID RSS, minimal exec-fixture RSS and isolated BPF-map allocations are not
substitutes for total memory or replacement savings. Compare CT lookup costs with
fixed rules, packet sequences, CPU, kernel and toolchain, using both kernel
`bpf-ns/op` and real UDP latency/throughput; map memory or a routing-cache-only
benchmark is not sufficient.

## Pre-commit Hook

This repo uses [pre-commit hook](https://github.com/pre-commit/pre-commit-hooks) to apply linting check prior to writing commit to local Git history. To set up pre-commit, do the followings:

```bash
# install pre-commit
pip3 install pre-commit
# install pre-commit hooks
pre-commit install
```

## How to make a clean pull request

- Create a `personal fork` of the project on GitHub.
- Clone the fork on your local machine. Your remote repo on GitHub is called `origin`.
- Add the original repository as a remote called `upstream`.
- If you created your fork a while ago be sure to pull upstream changes into your local repository.
- Create a new branch to work on! Branch from `next`.
- Implement/fix your feature, comment your code.
- Follow the code style of the project, including indentation.
- If the project has tests run them! For routine unit tests, use `make test`. For eBPF tests, use `make ebpf-test`.
- Write or adapt tests as needed.
- Add or change the documentation as needed.
- Squash your commits into a single commit with Git's [interactive rebase](https://help.github.com/articles/interactive-rebase). Create a new branch if necessary.
- Push your branch to your fork on GitHub, the remote `origin`.
- From your fork open a pull request in the correct branch. Target the project's `next` branch.
- Once the pull request is approved and merged you can pull the changes from `upstream` to your local repo and delete
  your extra branch(es).

And last but not least: Always write your commit messages in the present tense. Your commit message should describe what the commit, when applied, does to the code – not what you did to the code.

## Re-requesting a review

Please do not ping your reviewer(s) by mentioning them in a new comment. Instead, use the re-request review functionality. Read more about this in the [GitHub docs, Re-requesting a review](https://docs.github.com/en/free-pro-team@latest/github/collaborating-with-issues-and-pull-requests/incorporating-feedback-in-your-pull-request#re-requesting-a-review).
