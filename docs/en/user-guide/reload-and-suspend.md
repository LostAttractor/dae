# Reload and Suspend

## Reload

`dae reload` refreshes subscriptions, routing and plugin resources, then compares
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

The command waits for the daemon to confirm completion, with a three-minute
timeout. After 150 ms, terminal stderr shows a spinner with the current stage;
it clears before the result or error is printed. Redirected stderr and
`TERM=dumb` disable animation and retain ordinary progress lines on stdout.
The command submits an operation through the local Unix API and polls its unique
ID. Reload, suspend and resource refresh share a serialized queue of up to 16
pending requests. A full queue rejects new requests. A client timeout does not
cancel accepted work.

The local operation API remains available while routing is replaced. The daemon
retains the 64 most recently finished operations; unknown or expired IDs return
an error.

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
listeners and rules are ready. Only the explicitly registered daemon's own sockets
receive the bootstrap exemption; another process using the same mark does not.

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
