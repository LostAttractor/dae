# Connection State and Reload Lifecycles

`Runtime` owns the persistent listeners, kernel attachments, TCP connection set,
UDP endpoints, and connection maps shared across configuration generations.
A control plane and its `BPFState` own one configuration generation. Connections
retain the resources they need independently of that generation's retirement.

## Routing Handoffs

The kernel uses `control_plane_routing` for unresolved routing decisions. Setup
handoffs and the UDP route cache share the 40-byte `routing_result`, which has no
padding gaps. Its generation and device-policy identifiers serve different roles:

| Field | Byte offset | Meaning |
| --- | --- | --- |
| `route_epoch` | 0 | Device connection-policy version |
| `profile_id` | 16 | Routing profile within the configuration generation |
| `physinif` | 32 | Physical ingress interface |
| `generation` | 36 | Configuration generation |

The userspace `routingResult` embeds this result and retains the local process
name from the handoff, or the PID and process name of an internal request.

`routing_tuples_map` is a 16384-entry setup handoff LRU. Its 64-byte value contains
the full routing result, an expiry in monotonic seconds, the TCP initial sequence
number, and the local sender's process name for userspace `pname()` evaluation,
without padding gaps. TCP accept atomically retrieves and removes its handoff;
retransmitted SYN packets reuse the same handoff for up to 30 seconds without
extending its expiry. UDP reads a snapshot. Handoff capacity and expiry do not
control forwarding state for established TCP connections.

## TCP Flow Ownership

A TCP packet belongs to a proxy only while dae owns its tuple: through the setup
handoff until accept, then through the accepted socket in dae's network
namespace, which the kernel looks up directly. Proxy lifetimes begin with a SYN
that dae routes and end with dae's sockets, so no table has to remember them: a
cold start owns none, and normal shutdown resets them. A packet that neither owns
is native and keeps its own mark. This includes connections that predate the
datapath and late segments after dae's socket has gone.

`tcp_flow_map` is a bounded LRU of the properties of kernel-forwarded
connections, fixed by their SYN's routing decision. Its 24-byte `tcp_flow_state`
contains the device-policy version, mark, fallback token, and the SYN's sequence
number. Only a SYN that dae routes creates or replaces an entry, including for
ordinary unmarked direct connections, whose entry spares later packets the socket
lookup. The sender's RST is forwarded with the saved mark and then removes the
entry.

| Fallback token | Meaning |
| --- | --- |
| `0` | Direct flow not tied to a revocable fallback generation |
| `1` | Reserved invalid grant; never permits direct forwarding |
| Other values | Unique group/network fallback grant issued by userspace |

A packet whose entry is valid receives the saved mark. An entry becomes invalid
when its device-policy version changes or its fallback grant is revoked. Its
packets then enter the transparent TCP stack, whose listener resets the
connection so that it reconnects under current policy; offline, they are
dropped. LRU eviction removes a connection's properties, not the connection: it
continues natively with its packets' own mark and is no longer reset when its
fallback grant ends. First fragments cannot carry a mark or split across proxy
paths, so fragments of proxy-owned, marked, or invalid flows are dropped.

New outbound SYN packets establish a new decision; retransmissions with the same
initial sequence number retain it. Selecting a proxy removes the tuple's old
entry. A SYN-ACK answers an inbound handshake: it follows the tuple's entry if
one exists and never creates one. Inbound connections need no entry.

A fixed array of nonblocking, tuple-hashed atomic gates serializes handshake
decisions and reset cleanup. Contention drops the affected handshake packet for
TCP to retry, without spinning or blocking established data traffic. These gates
and `tcp_flow_map` are shared across reloads and pinned across process
replacement. Userspace has no per-flow cleanup timers and does not delete entries
by tuple.

The transparent listener sets `TCP_LINGER2` to a negative value to avoid keeping
FIN_WAIT2 sockets after dae's FIN has been acknowledged. This socket option is not
a deadline proving that every closing TCP socket has disappeared.

## Normal Stop and Unexpected Exit

Normal shutdown drains userspace and removes dae's host attachments, pinned state,
and internal network resources. It does not retain a second, offline daemon.
Once cleanup completes, ordinary network routing applies; dae no longer restores
marks or enforces routing and capture rules. Connections depending on those marks
can need to reconnect. A later cold start has no entries; connections that kept
running in the meantime remain native. An instance lock excludes concurrent
daemon ownership.

An exit that cannot complete cleanup, such as SIGKILL, leaves pinned programs and
`tcp_flow_map` behind. The exit hook marks this runtime offline. Its small
fallback datapath keeps applying valid entries and their marks. Proxy connections
end with the process's sockets and must reconnect; packets of a pending proxy
setup are dropped, and other unowned packets stay native.

`unexpected_exit_behavior` controls new managed outbound lifetimes:

- `bypass` (default) bypasses all old routing, block, DNS/MITM capture, and
  destination-rewrite rules. A new TCP handshake or UDP source retains the
  packet's original mark and receives an ordinary direct entry, not a group
  fallback lease. This favors availability and can expose traffic that would
  normally be proxied or blocked.
- `block` rejects new managed outbound lifetimes while preserving native traffic.
  Replies to inbound connections remain replies; this setting does not turn dae
  into an inbound firewall.

A UDP source still owned by a proxy binding or live proxy cache cannot escape by
changing its destination to DNS. Offline fragments without enough lifetime
identity are conservatively dropped. This mode is separate from
`no_connectivity_behavior`, which governs unavailable groups while userspace is
running; it does not run the old rule interpreter to select a replacement group.

Starting, online, and terminal offline states are distinct. Startup does not
activate crash bypass, and an offline runtime cannot publish another generation.
A new process takes over compatible crash-retained links and becomes online only
after listeners and its routing generation are ready. Only sockets owned by the
explicitly registered daemon process receive the bootstrap exemption; an equal
socket mark does not grant it. Process exit revokes the registration.

The two UDP maps containing BPF timers use private, per-runtime pins: a program
reference alone does not retain the userspace reference required by those timers.
They keep UDP handling usable after process death. A cold runtime creates fresh
UDP caches instead of adopting old group identifiers. Unreferenced timer pins are
reclaimed at lifecycle boundaries, not by a per-flow userspace GC.

A pinned monotonic counter prevents fallback token reuse across crashes. The live
set is process-local, so cold takeover can end old interruptible grants. Normal
cleanup removes the counter only after all older grants and attachments are gone;
failed cleanup retains it. Interface or host teardown and LRU pressure can still
end connections: crash retention is not an unconditional survival guarantee.

## Configuration and Plugin Handover

Persistent ingress loops dispatch setup work to the generation identified by the
handoff. Normal routing replacement leaves the old generation a 30-second setup
grace period, then stops setup and drains remaining MITM/DNS work. Preparing the
next routing generation waits for retirement, limiting configuration resources
to two generations at a time.

Plugin instance ownership determines the publication order for both full routing
replacement and in-place service replacement:

- Reused instances keep their workers running. If all instances are unchanged,
  old protocol hosts can drain asynchronously without delaying publication.
- Rebuilding instances first waits for earlier control planes and protocol hosts
  to retire, then pauses new admission while draining the current old host and
  completing final persistence before successor activation. Waiting callers honor
  their contexts; activation failure wakes them with an error. Workers shared with
  the successor remain active throughout this handover.
- Selecting a host and registering work form one admission under a short lock.
  DNS requests and TCP/QUIC connections retain that admission until completion.
  Already admitted work can finish on the old host and does not wait on the new
  admission barrier, including its auxiliary HTTP and internal DNS operations.
- MITM route preparation transfers one owner containing the admission, upstream
  planner, and any retained dialer. TCP and QUIC release that owner on setup failure
  or protocol completion; QUIC construction also owns cleanup on packet-budget
  rejection. Routing parameters carry routing data, not lifetime ownership, and
  the admitted DNS-address policy is passed explicitly during route selection.
- Each routing generation owns its protocol host, routing policies, outbounds,
  and connection drain together. Rebuilt plugin instances activate only on the new
  generation after the old host finishes draining. Late TCP/QUIC setups and DNS
  requests requiring the old host's policy admission fail with `net.ErrClosed`, even
  within its 30-second setup grace period; clients must retry on the new generation.
  This includes ordinary TCP setup, which consults the host's DNS-address policy.
  Reused instances keep their old protocol host and the normal setup grace period.
  New instances never
  execute requests with an old generation's routing or outbound declarations.
- An aborting replacement interrupts setup admission and wakes retired hosts,
  including hosts already inside Close. The abort callback remains registered
  throughout retirement and is removed afterwards. After retaining shared worker
  ownership, the current old host is canceled without a graceful drain delay.
  Final cleanup and persistence must still finish before the successor starts.
- A final flush or successor activation failure cannot roll back to an already
  closed instance. The daemon performs terminal cleanup instead.

Ordinary TCP relays and UDP sessions retain their selected resources independently.
Connection-policy leases acquired late from an old group follow its successor's
policy. Suspend, shutdown, and abort use `Runtime` to terminate connections and
release kernel return paths.

For the embedding and persistence contract, see the
[plugin lifecycle and storage documentation](../../../component/plugin/README.md#lifecycle).
