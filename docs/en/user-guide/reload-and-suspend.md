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

To abort established connections, including connections retained by earlier reloads:

```shell
dae reload --abort
```

`--abort` takes effect even when configuration and resource contents are unchanged. Aborting reload and normal daemon shutdown reset captured TCP sockets before releasing their kernel return paths. Uncaptured kernel-direct connections are not owned by the daemon. Forced process termination does not run this cleanup. Changes to `tproxy_port` or the effective `so_mark_from_dae` require a restart.

## Suspend

Suspend removes traffic interception using the accepted configuration and resources,
even if the configuration file or an external resource is currently unavailable.

```shell
dae suspend
```

If you want to recover, use reload:

```shell
dae reload
```
