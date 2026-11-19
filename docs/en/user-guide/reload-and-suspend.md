# Reload and Suspend

## Reload

Local `dae reload` compares the contents of its executable with the running
daemon. Identical executables use configuration reload; different executables use
[process replacement](#process-replacement). Version labels do not affect this
decision, so rebuilding the same development version is detected.

Configuration reload refreshes subscriptions, routing and plugin resources, then compares
effective inputs. Unchanged groups, physical paths and plugin instances keep their
transports, health/selection state, workers, caches and metrics. Refresh errors use
a complete validated fallback or reject the reload; preparation failures leave the
accepted configuration serving traffic.

This includes geoip/geosite/MMDB references in routing rules and plugin routing
plans. Reload compares the expanded rules, so changes to unreferenced entries do
not rebuild routing. File edits take effect on `dae reload`; suspend retains the
accepted resource data.

Reload also compares the local addresses used by the TCP API's exact address/port
bypass. An address change rebuilds routing even when configuration files are
unchanged, adding the new API address and removing stale exemptions.

| Change | Replacement |
| --- | --- |
| None | Keep the control plane and kernel generation |
| Logging, API credentials, observability | Update the corresponding service |
| Plugin inputs, same capture/routing declarations | Replace its protocol host and changed instances |
| Routing or capture inputs | Prepare private kernel routing state, reuse unaffected instances |

Established ordinary TCP connections survive unless a configured connection policy
closes them. Replaced MITM hosts drain requests; DNS TCP connections close when
their control plane retires.

Listeners and connection state belong to a persistent runtime. TCX links update
in place, one interface at a time; failure after attachment replacement begins is
terminal. Queued TCP setups retain their original configuration for up to 30
seconds, including SYN retransmissions. Expired or evicted handoffs are reset.
Preparing another kernel generation waits for the old generation's retirement.

Usage:

```shell
dae reload
```

The command waits for the daemon to confirm completion, with a four-minute
timeout. After 150 ms, terminal stderr shows a spinner with the current stage;
it clears before the result or error is printed. Redirected stderr and
`TERM=dumb` disable animation and retain ordinary progress lines on stdout.
The command submits an operation through the local Unix API and polls its unique
ID. Reload, suspend and resource refresh share a serialized queue of up to 16
pending requests. A full queue rejects new requests. A client timeout does not
cancel accepted work.

During configuration reload, the local operation API remains available while
routing is replaced. The daemon retains the 64 most recently finished operations;
unknown or expired IDs return an error. Process replacement has a separate API
interruption, described below.

To abort established connections, including connections retained by earlier reloads:

```shell
dae reload --abort
```

`--abort` takes effect even when configuration and resource contents are unchanged. Aborting reload and normal daemon shutdown reset captured TCP sockets before releasing their kernel return paths. Uncaptured kernel-direct connections are not owned by the daemon. Forced process termination does not run this cleanup. Changes to `tproxy_port` or `so_mark_from_dae` require a restart.

## Normal Stop and Unexpected Exit

Normal service shutdown removes dae's kernel attachments, pinned state, and
internal network resources. Ordinary routing then applies without dae's marks,
block rules, capture, or destination rewriting. Connections that depend on those
marks may need to reconnect; there is no separate unload command. Starting dae
again does not reset connections that kept running; they stay on ordinary routing
until they end.

Unexpected termination that cannot finish cleanup, such as SIGKILL, retains a
small kernel fallback datapath. Valid native connections keep their saved marks;
established proxy TCP connections end with dae's sockets and must reconnect.
Panics skip normal cleanup to apply the same unexpected-exit policy.
Choose the policy for new managed outbound connections in `global`:

```dae
global {
    unexpected_exit_behavior: bypass
}
```

`bypass` is the default. It bypasses **all** old routing, block, DNS/MITM capture,
and destination-rewrite rules for new TCP handshakes and new UDP source lifetimes.
Connections admitted by crash bypass can remain direct after restart; recovery
does not splice them back into a proxy. Choose `block` if that exposure is not
acceptable; existing valid native traffic and proven inbound replies remain
allowed. This is independent of
`no_connectivity_behavior` for unavailable proxy groups while dae is running.
Both modes rely on the retained hooks; they do not govern unmanaged interfaces or
traffic after those hooks have been detached.

A restarted daemon takes over crash-retained links and becomes online when its
listeners and rules are ready. A restart that fails before then leaves the crash
fallback in place. Only the explicitly registered daemon's own sockets
receive the bootstrap exemption; another process using the same mark does not.

## Process replacement

Process replacement is a **restart with failure protection**, not a globally atomic
or lossless handoff. Failures before Block leave the old service running. After
Block, closing old connections cannot be rolled back; failures keep managed traffic
fail-closed until successful recovery. Direct traffic is not guaranteed to remain
uninterrupted.

Use an installed CLI to select a trusted replacement binary, run the new CLI
itself for automatic content comparison, or force replacement with the CLI's
own executable:

```shell
dae reload --binary /path/to/new/dae
/path/to/new/dae reload
dae reload --replace
```

With `--binary`, the path is relative to the CLI's working directory unless
absolute, including when the CLI needs to elevate before opening the file.
Selecting it forces replacement even if the contents are identical.
The CLI pins the selected file, so changing a symlink or renaming the path does
not change the selection. Do not overwrite the file in place during replacement.
The daemon authenticates the local Unix peer and opens the selected file
descriptor, or the peer's own executable when no path was supplied.
It uses its own effective run arguments, environment and working directory for
both preflight and exec, not the invoking CLI's environment. No executable path
is accepted over the API. Remote API reloads remain configuration-only; both
`--binary` and `--replace` are local-only.

`dae run` takes an exclusive `/var/run/dae.lock` file lock before reading the
configuration. Another instance using the same runtime directory is rejected,
even during startup or exec; use `dae reload` to change the running instance.
The lock FD survives exec and the kernel releases the lock when its last owner
exits. A leftover unlocked file does not prevent startup; do not delete a live
instance's lock file. CLI commands and the temporary preflight helper are not
additional business instances.

A short-lived target ELF process runs its parser, plugin `Preflight` and kernel
checks, then prepares a userspace control plane without business BPF. Before
Block, it reads and validates configuration/include selections, subscriptions,
modules and dependencies, geodata and complete static plugin plans. It does not
read settings or DomainRegistry, construct live plugin instances, run `Warm` or
plugin workers, build a complete Runtime or publish client sets. The old dataplane
and API keep serving during downloads and validation; new configuration operations
return 409. The parent revokes the helper's PID exemption before reaping it.
Successful prefetch is not a guarantee that full startup will succeed.

The accepted raw inputs travel in a separate sealed memfd: at most 128 MiB for an
input or complete resource group, and 512 MiB for the entire archive. Configuration
bytes and include/glob selections, asset locations and bytes, complete cache-group
results and failures, and decisions to skip subscriptions are frozen together.
After exec, initialization strictly replays those inputs, even if source files
change or disappear or a server becomes unavailable. Missing, corrupt,
inconsistent or oversized inputs fail the operation; they never trigger live I/O
fallback. The archive does not carry live plugin objects, the old heap, settings
or Registry state. Recording/replay contexts are not retained by runtime services
or subsequent reloads.

After preflight, the daemon collects inherited FDs and encodes and seals the
handoff description before draining active management API requests. Encoding,
size-limit or sealing failures leave the old API and business running.
Management reads and writes handled by the drained servers return 503. The
existing local operation route can still answer until its server closes, but
queries are not available throughout replacement: exec retains listener FDs,
not Go HTTP servers, so requests may time out or disconnect before the new
servers resume. The CLI retries operation reads, not the submission. Fixed
`dae0`, `dae0peer`, `daens` and unchanged API/observability listeners retain their
identity through inherited FDs. The sealed handoff also carries the daemon's
process name. Startup restores it before any routing or resource initialization,
so `pname()` rules for internal DNS, resource downloads and workers keep matching
after FD-based exec.

Before closing old connections, the daemon sets its entry programs to
`STOPPING`: only proven explicit-direct traffic, necessary control protocols and
restricted daemon/preflight identity exemptions remain allowed. Proxy/captured,
fallback, uncertain traffic and non-first fragments are dropped. Fallback zero
does not prove explicit direct. This active blocking state is separate from
ordinary `unexpected_exit_behavior`; crashes still use the configured bypass/block
policy. Old TCP sockets and listener backlogs close through
the unchanged old return path, allowing idle clients to receive RST without first
sending another packet. RST delivery across the network is not guaranteed.
Existing explicit-direct traffic may continue through a single old guard while
its evidence remains valid. Old and new guards use private maps with no
cross-generation direct evidence: during overlap, the new guard may block traffic
allowed by the old guard. A later failure can extend that pause until successful
recovery; neither uninterrupted direct traffic nor a bounded pause is promised.

The single business process explicitly closes its old Runtime, flushes state and
reaps plugin descendants before executing the already-open target ELF with the
same PID and process starttime. No resident supervisor or separate business worker
is involved. The old Go heap and goroutines disappear; cleanup cannot rely on
defers running after exec.

The new image reads final settings once, rebuilds userspace objects from the
frozen inputs, then loads private business BPF, constructs plugin instances and
runs `Warm`, then restores DomainRegistry and prepares its private kernel
projection while old guards still block captured traffic. Minimal host
socket-owner hooks precede persistent proxy sockets; business BPF follows
userspace preparation. At commit, it prepares client exports before locally
updating the downstream socket, ingress and DNS reply links and attaching new host TCX programs after the old guards.
Both generations retain independent maps. Temporary old WAN socket-owner hooks
remain separate from the new runtime's hooks until old guards retire. Each
writes its own `socket_owner_map`; formal startup re-registers the daemon in the
old guards' `daemon_identity_map` without sharing business maps or exempting other
processes. Preflight uses a separate temporary PID exemption, revoked before
reaping and also cleared by the kernel if the daemon or candidate exits.
After installation, the same commit applies the prepared client ipset/nft exports,
starts plugin workers and enables Registry persistence.
It validates complete hook coverage, publishes its own canonical pins, releases
old guards incrementally and enters `ONLINE`. Installation and retirement across
multiple hooks are protected intermediate states, not a globally atomic
transaction. `ONLINE` is this runtime's dataplane activation point; READY is a
readiness notification, not a globally atomic commit receipt. Its own guard bundles
and interface freeze remain while the daemon validates every attachment and sends READY
within the original deadline. Only then does it claim the canonical pins and remove
`/sys/fs/bpf/dae/replacement_pending`. This marker protects partial publication
even when no interface matches the capture rules. Fixed network objects and the Unix API socket
also remain borrowed until final readiness. A late READY failure or cancellation
can still re-enter `STOPPING` and terminate the successor while retaining recovery
protection. This handles a failure after dataplane activation; it neither ignores
READY failure nor resumes the old process. Traffic during the interruption is
dropped; replacement does not queue it, preserve active sessions or promise an
interruption below a fixed threshold.

Socket lookup delivers traffic only when its runtime is `ONLINE`. UDP source
associations support multiple destinations without a routing handoff for every
packet. Replacement closes the old associations; the ready successor requires
its own valid routing handoff to create an association, or uses an existing new
association. DNS keeps per-destination routing. UDP connection state, inbound
pending, bindings, caches and timers remain in use. A new private generation needs
host CT evidence: only `CT_ORIGINAL` creates inbound pending state, and only
`CT_REPLY` restores inbound replies. CT miss/NOTRACK is not direct evidence;
late WAN relay replies without matching CT REPLY are dropped. Late packets follow
the same admission rules; missing routing information never causes a direct fallback.

After successful replacement, TCP follows ordinary restart semantics. A short-lived
handoff leads to the real accepted proxy socket; an optional SOCKHASH index falls
back to proxy network-namespace socket lookup if full or registration fails.
The LRU `tcp_flow_map` holds only native routing properties, not proxy admission or
FIN/ACK state. Unknown non-SYN packets are native once `ONLINE`, so replacement
does not promise to reject every old unknown ACK after success. LRU eviction can
lose saved marks and fallback constraints without closing the actual connection.
Non-first fragments are blocked during `STOPPING`; once running, first-fragment
routing checks allow direct datagrams to reassemble and reject proxied fragments.
ARP and other supported, non-captured control protocols remain available while
stopping.

Failures before blocking leave the old runtime serving and shared client exports
unchanged. Canceling the API drain reopens the existing handlers. A service
notification failure during a recoverable operation fails that operation and leaves
the daemon serving. Once blocking begins, failures are terminal for that handoff: the old
runtime is not resumed, and pinned entry guards under `/sys/fs/bpf/dae/guards`
remain even if the process exits. Downloads and static-input validation happen
before Block, including rejection of overlapping API, pprof and metrics ports.
A replacement can swap these ports by releasing obsolete listeners before binding
the new addresses. Invalid final settings, ports occupied by other processes, instance construction,
script `Warm`, real business BPF loading, and client export preparation or
publication may still fail after this boundary. A strict replay failure also
retains protection rather than fetching replacement inputs. Partial publication or later
activation failure keeps the applied sets and blocking
guards while cleaning temporary export backups; it does not roll back to the old
sets. After commit, failures to remove redundant guard bundles or unreferenced old
UDP timer pins only log warnings, as does successful takeover's export-backup
cleanup. State/topology validation errors and failure to retire old guards before
commit completes remain fatal. Ordinary configuration reload retains its export
rollback behavior.
A subsequent successful startup removes persistent guards only after its own ready
entries cover the guarded hooks. Restore the original
interception interface configuration if coverage validation fails. A failed
coverage check does not add new persistent guards. Only replacement and guard
recovery start with private business maps rather than adopting predecessor pins;
normal operation publishes canonical pins, and ordinary restart reuses compatible
pins. Each guard bundle retains its entry link, UDP connection-state and routing-cache
timer maps, socket-owner writer links, exit hook and daemon identity map. There is
no TCP timer. Retirement releases both canonical and guard references; old identity
writers are not replaced through same-name pin updates. Failed startup reclaims
private runtime timer pins that no attached entry or guard references, so repeated
failures do not accumulate unused maps. If references cannot be inspected, cleanup
keeps the pins and reports the error rather than risking an active guard.
Failed handoffs never silently choose restart or bypass traffic protection. During
cold recovery, old guards still block ordinary captured traffic. The newly
registered daemon identity may fetch startup resources through its restricted
exemption; this does not guarantee upstream availability or exempt other processes.

Connections, DNS sessions, in-memory caches and counters are not migrated.
Prefetch uses only old in-memory selector hints, not persisted settings.
Persisted selections and client membership come from the new image's single
settings read after the old API closes and exec completes. DomainRegistry first
restores during kernel preparation, before new host entries are installed and
after the old writer closes and finishes its final flush;
the new writer reads that final state before enabling persistence, preserving
single-writer ownership. Other caches and certificates retain their own preparation
contracts. Surge's
[persistent store](../../zh/configuration/surge-module.md#持久存储) loads contents
only on actual script read/write, not runtime construction, warmup or close.

Replacement requires unchanged LAN/WAN interception lists, their resolved interface
and attachment sets (including automatic WANs and wildcard matches), and the
existing fixed network topology. Apply interface-list edits with the running executable first,
or restart explicitly. Changes to the run arguments, environment, systemd
credentials or fixed topology also require an ordinary restart. A replacement may
change the transparent listener port and socket mark because its connection state
is private. Replacement has a three-minute transaction deadline that is preserved
across exec. Once blocking starts, the old runtime has a separate 15-second
shutdown watchdog, including stuck plugin cleanup. Stop signals and the remaining
deadline are checked before exec. The new image has startup deadline protection,
but the old Go watchdog cannot survive exec: an ELF loader or package initializer
that hangs permanently still needs an external service manager. There is no
resident watchdog. Concurrent configuration operations return 409 while the API
can answer during replacement; already queued work must finish first. Successful
replacement completes the original operation ID with the unchanged PID and new
version; cold recovery after a failed handoff does not restore that operation.

For service deployment, see [systemd and NixOS](run-as-daemon.md#binary-upgrades).
For resource ownership and state details, see the
[process replacement design (Chinese)](../../zh/design/process-replacement.md).

## Suspend

Suspend removes traffic interception using the accepted configuration and resources,
even if the configuration file or an external resource is currently unavailable.
It does not download resources, but may wait for earlier control-plane retirement
and active API requests before publishing the replacement routing. The command
uses the same completion checks, timeout and progress display as reload, and
returns success only after the daemon confirms suspension. Existing connections
are retained unless `--abort` is specified.

```shell
dae suspend
```

If you want to recover, use reload:

```shell
dae reload
```
