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

## TCP Flow State

Long-lived TCP forwarding uses a separate 16-byte `tcp_flow_state` containing the
device-policy version, packet mark, and owner:

| Owner | Meaning |
| --- | --- |
| `0` | Ordinary kernel-direct forwarding |
| `1` | Redirect to the userspace proxy |
| Other values | Token for a kernel-direct fallback generation |

Userspace allocates fallback tokens excluding both reserved values. Ordinary
direct forwarding without a mark, device-policy version, or fallback token needs
no flow entry.

The kernel owns flow-state transitions:

- For a kernel-forwarded flow, the initiating peer's RST is forwarded using the
  saved state and then removes the entry. Later RST packets no longer inherit its
  mark.
- For a proxied flow, neither an RST nor relay completion removes the entry. Late
  closing packets still reach dae rather than the original destination. A flow-state
  cache miss also checks for a live proxy socket in dae's network namespace:
  complete packets still redirect to it, while first fragments are dropped rather
  than routed to the original destination.
- A new outbound SYN replaces the tuple's state using current routing. A plain
  direct decision that needs no state removes the old entry.
- A SYN-ACK can replace an old proxy entry with direct state only after its setup
  handoff has expired or been consumed and no live TCP socket owns the tuple in
  dae's network namespace. The kernel queries its socket table, not a userspace
  lease or timer; listeners and TIME_WAIT entries do not count as live proxies.
  This keeps delayed SYN-ACK packets from rerouting an accepted proxy connection.
  Direct state uses the current device version and packet mark, or removes the
  entry if neither is needed. A remote SYN alone does not change proxy state.
- Remaining idle entries are reclaimed by the bounded LRU. Userspace does not
  delete TCP flow entries by tuple.

The transparent listener sets `TCP_LINGER2` to a negative value. If dae closes
before the client, acknowledging dae's FIN resets the client instead of leaving a
socket that can keep sending after the relay has ended.

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
