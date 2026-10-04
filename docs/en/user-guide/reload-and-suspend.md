# Reload and Suspend

dae supports configuration reloading and program suspending, which can help you save a lot of time when modifying the configuration or temporarily suspend dae.

## Reload

Reload preserves established ordinary TCP connections unless a configured connection policy closes them. MITM requests drain before their connections close; DNS TCP connections close with the old DNS relay. Reload also refreshes subscriptions.

Listeners and connection state belong to a persistent runtime. Each configuration has private routing maps and programs; reload updates existing TCX links without detaching them or pausing routing. Interfaces switch individually, so they may briefly use different complete configurations.

Queued TCP setups keep their original configuration for up to 30 seconds. SYN retransmissions preserve that handoff; expired or evicted handoffs are reset. The old configuration then drains MITM and DNS work. A subsequent reload waits for that retirement before preparing another generation, bounding overlapping configuration resources.

Usage:

```shell
dae reload
```

To abort established connections, including connections retained by earlier reloads:

```shell
dae reload --abort
```

Aborting reload and normal daemon shutdown reset captured TCP sockets before releasing their kernel return paths. Uncaptured kernel-direct connections are not owned by the daemon. Forced process termination does not run this cleanup.

## Suspend

It will be useful if you want to suspend dae temporarily and recover it later.

## Usage

```shell
dae suspend
```

If you want to recover, use reload:

```shell
dae reload
```
