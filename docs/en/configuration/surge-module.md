# Surge Module

The built-in `surge` plugin selects its JavaScript backend at build time: QuickJS-NG through [buke/quickjs-go](https://github.com/buke/quickjs-go) by default, or Node.js in an alternative build. The plugin focuses on Surge request/response scripts for MITM, with module rewrites, storage, DNS, cron, and generic scripts as supporting features. HTTPS uses a local CA, and the feature is disabled by default. See [supported features](../../zh/configuration/surge-module-support.md) and the [build guide](../user-guide/build-by-yourself.md#surge-javascript-runtime).

## Configuration and Operation

Add the following settings to the main configuration. dae automatically initializes a persistent CA; have clients [install and trust the certificate](../../zh/configuration/certificate.md) before adding them to `client_source_address`:

```text
global {
  api_port: 9080
  resource_cache: true # Enabled by default; shared cache for subscriptions, modules, and remote dependencies
}

mitm {
  enabled: true
  # Replace with the MAC of a client that trusts the CA; use 'all' to enable all clients.
  client_source_address: '02:00:00:00:00:50'
}
plugins {
  surge {
    module {
      demo: 'file:modules/demo.sgmodule'
      # The name is optional; declaration order determines matching priority:
      # 'https://example.com/module.sgmodule'
    }
  }
}
```

Plugin instances belong in `plugins {}`. See [plugin configuration](../../zh/configuration/mitm-plugins.md) for multiple instances.

Declare modules as `name: 'source'` or an anonymous `'source'`; argument configuration is covered in the next section. Names must be unique. The display name uses the configured name first, then `#!name`, then the filename.

| Source | Behavior |
| --- | --- |
| `file:modules/demo.sgmodule` | Relative to `DAE_LOCATION_CACHE`, which defaults to `/var/lib/dae` |
| `file:///opt/dae/demo.sgmodule` | Absolute path |
| `http://`, `https://` | Tries the network first; when `global.resource_cache` is enabled, saves a complete snapshot of the module and its dependencies and falls back to that snapshot as a whole on failure |

Use the top-level `certificate` section for a custom CA; relative `ca_cert` and `ca_key` paths use `DAE_LOCATION_CACHE`. Persistent script storage is enabled by default and automatically saved to `plugins/<instanceID>/surge-store.json` under that directory. Relative script and Map Local paths within a module resolve against the module directory or the final URL after redirects. Remote modules cannot read local files, and HTTPS downloads cannot downgrade to HTTP. `global.resource_cache` is enabled by default for all HTTP(S) modules and dependencies; local files always use their current contents. Cache entries are distinguished by source and explicit arguments, not by name. See [cache directories](../../zh/configuration/cache-directory.md#全局资源缓存) for write and directory rules.

Modules and scripts are trusted configuration and can access the local network through dae. `http_policies` declares outbounds to preload; it is not a permission allowlist. Load only trusted sources. When a module or dependency uses HTTP, logs and module status warn that the content can be tampered with in transit; an HTTP-to-HTTPS redirect or cache fallback does not remove this warning. HTTPS modules cannot reference HTTP dependencies, and HTTPS downloads of modules or dependencies cannot redirect to HTTP. HTTPS protects transport, not the trustworthiness of the module's author or content.

At startup or reload, dae waits for the initial node connectivity checks to finish, resolves module hosts with the system resolver, downloads modules through normal routing, and takes over traffic after loading completes. Initial checks wait at most 60 seconds; on timeout, startup continues under the existing offline policy. The module list shares a two-minute refresh budget, and each module's own rules take effect only after it loads. Loading fails when neither a source nor a cache is available; a failed reload keeps the old instance. Reload stops new requests to the old instance and drains its requests within a five-second budget; ordinary TCP/UDP connections follow their own lifecycles. Remote scripts are checked automatically according to `script-update-interval` in seconds, default `86400`, with `0` disabling checks. Modules, subscriptions, and ordinary dependencies use `global.resource_update_interval`. Reload and the [resource refresh API](api.md#resource-refresh) attempt an immediate refresh.

| Setting | Default | Meaning |
| --- | --- | --- |
| `node_path` | `node` | Accepted only by Node.js builds: an executable path or a name in PATH; command-line arguments are not accepted |
| `script_timeout` | `5s` | Default execution budget per stage; HTTP stages include body decoding, rewriting, and in-script HTTP requests, but exclude reading the original body and waiting for an instance execution slot. DNS and background tasks still include queueing. An explicit script `timeout` in seconds takes precedence |
| `memory_limit` | `134217728` | QuickJS heap limit per invocation; for Node.js, the V8 old-generation limit per worker process, rounded down to MiB; specified in bytes |
| `max_body_size` | `33554432` | Body buffering limit in bytes; scripts can lower it further |
| `max_concurrent_scripts` | `16` | Shared concurrency slots for rule matching, rewrites, scripts, and diagnostics |
| `http_policies` | Empty | Comma-separated outbound groups to preload for script-initiated requests, such as `proxy,api`; does not add capture or routing rules |
| `isolate_lan` | `true` | Isolates LAN script state by trusted MAC by default; dae module descriptors can override this per module or script. Local execution always uses the local partition |
| `store` | `true` | Whether to persist `$persistentStore`; `false` keeps it only in instance memory. The filename is determined automatically |

Each script invocation creates an independent execution context. The default script `max-size` is 1 MiB; modules are limited to 4 MiB, individual dependencies to 16 MiB, and all dependencies together to 64 MiB. JavaScript heap limits are not process memory limits. Node.js `memory_limit` constrains only V8's old generation; workers also have the cgroup limits described below. jq has its own process memory limits.

### Node.js Backend

Build dae with `make SURGE_RUNTIME=nodejs` and install Node.js 22.13 or later on the system running dae. This build defaults to `CGO_ENABLED=0` and does not compile or link QuickJS. To specify the Node.js path, set it in the plugin instance:

```text
plugins {
  surge {
    node_path: '/usr/bin/node' # Use the installed path; if omitted, dae looks for node in its PATH
    module {
      demo: 'file:modules/demo.sgmodule'
    }
  }
}
```

Node.js runs as an external process, with no npm packages or additional script files required. Once module resources are ready, only instances containing scripts create and prewarm a runtime using `node_path`; failure rejects the candidate configuration and preserves the running instance. Modules containing only Host entries, rewrites, or other non-script features do not need a JavaScript runtime. Each binary contains one script backend, used by every Surge instance; the configuration does not offer runtime switching. `make SURGE_RUNTIME=quickjs` builds the QuickJS backend, which does not require Node.js to run scripts.

Each module may contain at most 1024 regular expressions for HTTP matching and replacement. An HTTP request and its response share a cumulative regex execution budget of 250 ms and a limit of 4096 regex operations; diagnostic queries use the same budget. Timing covers only regex execution, not upstream network waits or body reads. Each regex also has its own timeout, so the final operation may exceed the cumulative budget because of the underlying timeout-check granularity. Budget exhaustion or an individual regex timeout stops the current processing. Diagnostics return incomplete results marked `regex_budget`, rather than treating unevaluated conditions as definite non-matches.

An execution slot is acquired before HTTP rule matching. Queueing respects request cancellation and does not consume the script execution budget. The slot is released while reading a body from the network; after the read completes, the request queues again for a slot, then starts the budget for body decoding, rewrites, and scripts. The slot is also released during upstream forwarding. Slow uploads or downloads therefore do not occupy execution slots needed by other requests. URL/header regex replacement results are limited to 1 MiB; body replacements remain subject to body-size and shared-memory limits.

Instances containing scripts prewarm one worker during preparation, completing protocol initialization and compilation of the shared bootstrap without executing user scripts. Prewarm failure rejects the startup or reload without affecting the currently running configuration. Instances containing only rewrites, Hosts, or routing rules do not create a JavaScript runtime. Additional processes start on demand as concurrency increases, up to `max_concurrent_scripts`. Maintenance runs every five seconds and reclaims excess workers after 60 seconds of idleness, retaining the most recently used idle worker. Processes executing scripts or waiting for script HTTP requests or timers are not reclaimed as idle. Every script execution uses a fresh, independent context. Closing an instance terminates and reaps its processes. A script timeout, cancellation, execution exception, or process crash discards that worker; a later invocation creates a replacement. Cold starts during expansion or replacement, cross-process body copying, and synchronous host calls add overhead. CPU-intensive scripts may benefit from V8, but short scripts are not guaranteed to be faster. Node.js workers typically use more memory than QuickJS.

Node.js prewarming requires writable cgroup v2 with the memory controller delegated. Each worker has `memory.max` set to `2 × memory_limit + 64 MiB` and `memory.swap.max` set to 0. The parent group's limit is that amount multiplied by `max_concurrent_scripts + 1`; the extra allowance covers kernel accounting that has not yet been released for exiting processes. These limits cover heaps, ArrayBuffers, native allocations, and related kernel memory charged to the cgroup. They are not equivalent to RSS/PSS and do not cover bridge buffers in the dae host. Processes enter their groups directly at creation. Reclamation terminates processes in the group, waits for them to exit, and deletes the group; the parent's reclamation allowance avoids turning delayed accounting updates into a wait on every script invocation. The fixed runtime allowance needs calibration for the target Node version and workload. Each instance, including old and new runtimes overlapping during reload, has its own parent-group allowance.

The repository's systemd unit uses `Delegate=memory` and `DelegateSubgroup=daemon`, requiring systemd 254 or later; custom services must also set both. Node and jq resource groups always remain inside their owning service and never cross a service, scope, or slice boundary in search of permissions. The service's `MemoryMax` therefore still covers dae, all workers within the service, and old and new instances overlapping during reload. Other process managers must place dae in a leaf group in advance and provide a writable parent group with the memory controller enabled; dae does not move its host process. Insufficient delegation causes loading to fail rather than falling back to unlimited execution. A kernel OOM kill is returned as an explicit script execution error. It can be triggered by a worker limit, an ancestor-group limit, or system-wide memory pressure, so the event alone does not prove that the worker reached its own limit. A replacement can be created after the failed process and its descendants are reclaimed. Failed cleanup retains resource ownership and retries in the background, pausing new work for that pool in the meantime. The pool resumes accepting work after cleanup, unless it has entered final shutdown.

`dae plugins surge status` and `dae plugins status --verbose` show busy/idle pool counts, capacity, startup/reuse/reclamation/failure counts, and RSS/PSS. They also show cgroup current usage, peak, limit, kernel OOM-kill count, and sample age; these values share a cache with Prometheus. Memory is sampled in the background every five seconds, and queries only read the cache. Output includes the number of sampled processes and the oldest sample's age; an unsampled process does not imply zero usage. PSS apportions shared pages proportionally and is more suitable for observing pool memory than simply summing RSS. Prometheus exposes equivalent `dae_plugin_surge_nodejs_*` metrics; see the [metrics reference](metrics.md#surge). Startup probes use a separate temporary pool and are excluded from operational process counts. The prewarmed worker retained during preparation counts as an operational startup; instance shutdown does not count as failure or idle reclamation.

Both backends use the same Surge APIs, storage, timers, and Go HTTP client. Script-initiated requests remain subject to dae outbound policies and body budgets. Scripts can read `quickjs` or `nodejs` from `$environment['dae-runtime']`. The Node.js backend does not expose `process`, `require`, native modules, files, or direct network APIs, and does not inherit process environment settings such as `NODE_OPTIONS` or `NODE_PATH`. It uses isolated contexts and Node's permission model, but [node:vm is not a security sandbox](https://nodejs.org/api/vm.html). Load only trusted scripts.

### Persistent Storage

Storage is partitioned by **instance × effective execution scope × key**. Local invocations always share the instance's local partition. The instance-level `isolate_lan` defaults to `true`; dae module descriptors can set module-level `isolate_lan` or override individual scripts with `script { name: 'script-name' isolate_lan: false }`. Precedence is **script override > module override > instance default**, with unspecified values inherited at each level. This applies to HTTP request/response, DNS, cron, and generic scripts. No changes to sgmodule files, JavaScript, or persistent keys are needed. Isolated LAN invocations use a separate partition identified by the host-confirmed MAC of the directly connected device. When the source is unknown or its LAN identity cannot be confirmed, `read` returns null, and `write` and deletion return false; an IP, gateway MAC, or zero MAC is not used to infer a local identity. Disabling isolation makes all sources share the local partition. A default filename is `/var/lib/dae/plugins/surge/surge-store.json`; renaming an instance uses a new file and leaves the old file intact. `store: false` controls persistence only, not isolation. It neither reads nor modifies an existing file; in-memory data is lost on reload, and re-enabling persistence restores the data in the file.

The JSON structure within a file is `partitions → keys → strings`, with a reserved partition name for local execution and canonical MACs for devices. All partitions together are limited to 64 MiB, and each value to 4 MiB. Within the same instance and effective execution scope, HTTP, DNS, cron, and generic scripts share the original keys, without further partitioning by script or module. Omitting a key uses the resolved script-path, so identical paths share the default entry. Explicit keys must be nonempty strings without path separators. Values must be strings; null deletes an entry. Writes use a cross-process `surge-store.json.lock` in the same directory, merge the latest data, and replace the file atomically. Reads check file identity, size, and modification time, reloading JSON only when these change. Lock waits are bounded by the script timeout, and data and lock files use mode `0600`. Individual key writes are concurrency-safe; multiple read/write operations do not form a transaction.

A capture script that saves a Cookie and the cron/generic script that reads it must use the same isolation policy and effective execution scope to access the same state. For example, in a dae Surge instance, make the module's capture and job scripts shared while leaving other scripts isolated by the module default:

```text
module {
  account {
    link: 'file:modules/account.sgmodule'
    isolate_lan: true
    script { name: 'capture' isolate_lan: false }
    script { name: 'job' isolate_lan: false }
  }
}
```

If the entire module needs shared state, set the module's `isolate_lan: false` directly instead of listing every script. The `script` descriptor can be repeated, but every entry must contain a nonempty name and a boolean isolate_lan, with no duplicate names. Names match script names exactly after module argument substitution and condition filtering, and may contain Chinese characters, dots, and spaces. No match or multiple matching definitions cause loading to fail. Identically named scripts in different modules do not affect one another. Descriptors can coexist with `arguments {}` and do not add Surge arguments or header metadata. Remote module updates do not overwrite local policies, but renaming or removing a script requires updating its descriptor.

Disabling isolation intentionally shares Cookies/tokens between clients and the local host; later writes may overwrite another account's data. Changing isolation settings changes only the partition accessed, without automatically migrating, merging, or deleting existing partitions. A MAC is a device identifier, not an authentication credential; changing or reusing a MAC changes or inherits its partition.

### Migrating Data After a MAC Change

After a device changes its MAC, move its entire script-storage partition through the running daemon:

```bash
dae plugins surge store migrate 02:00:00:00:00:11 02:00:00:00:00:22 --instance surge
# Add --json for automation; standalone dae-client uses the same plugins subcommand.
```

The positional arguments are the old and new MAC, in that order. First stop traffic from the old MAC and revoke its eligibility for background execution, then verify the new address and destination partition before migrating. Neither device needs to be online or currently MITM-enabled; the command requires administrative access. Without `--instance`, exactly one Surge instance must exist; the command does not process multiple instances in bulk.

- Migration preserves all keys and values and deletes the old partition on success. It does not split data by script or module and does not touch the local partition.
- A missing source partition returns `404`; an existing destination partition, even an empty one, returns `409`. There is no overwrite, merge, or force mode. An invalid MAC or identical source and destination MACs return `400`.
- If a script is executing for either MAC, the command returns `409` without interrupting it. Retry after the script has fully cleaned up. Executions for unrelated devices, the local scope, or unknown scope do not cause this conflict. Disk writes reuse the existing lock and atomic replacement; lock waits are bounded by the server's five-second context budget, while filesystem I/O is not guaranteed to be immediately interruptible.
- On success, device-scoped DNS script caches using the same store are invalidated; local caches are unchanged. Responses already in flight and external DNS caches cannot be recalled.
- Migration does not move notifications, task history, MITM authorization, client sets, or routing rules, and does not rewrite queued tasks' MACs. It is not a permanent alias: new executions for the old MAC may recreate the old partition. Device authorization must be adjusted separately.
- With `store: false`, only the running instance's in-memory data is moved; there is no disk access or added retention across reloads. An instance without a script runtime returns `503` and does not open historical files.

Success returns the number of keys moved. `--json` includes `instance`, canonical `from_mac` and `to_mac`, and `keys_moved`, without exposing stored values. If atomic replacement completes but directory synchronization fails, the command returns `500` and explicitly states that the migration has been published but durability is unconfirmed. The data has already moved, so do not retry automatically. A timeout or connection loss also does not prove that the data is unchanged; the CLI does not retry automatically.

Execution-time protection covers the current daemon and reload generations sharing the same path. The cross-process file lock protects only individual updates, not another process's entire script read–compute–write sequence. If another process accesses the same store, stop its writes before migration. A MAC is not authentication; migration may transfer Cookies/tokens, so administrators must confirm that the new MAC belongs to the intended device.

## Module Arguments and Interactive Configuration

Modules declare arguments with `#!arguments=name:default,...` and reference them in the body as `{{{name}}}`. Chinese names are supported, and names are case-sensitive. Substitution is literal, without automatic JSON encoding. Unknown or duplicate arguments, missing required arguments, and values containing newlines or NUL cause errors.

```sh
dae plugins surge configure 'file:modules/youtube.sgmodule' \
  --name youtube > youtube-module.dae
```

The command displays the module description and arguments. Press Enter to inherit a default, enter an explicit value to pin it, or use `""` for an empty string. Arguments without defaults require a value. Only explicit argument and isolation overrides are written to the configuration; with neither, the command generates the shorthand form. `--name` defaults to `module`.

Prompts go to stderr. Place the `module` section written to stdout inside the corresponding Surge instance in `plugins`. For example:

```text
module {
  youtube {
    link: 'file:modules/youtube.sgmodule'
    arguments {
      '屏蔽上传按钮=false'
      '字幕翻译语言=zh-CN'
    }
  }
}
```

You can also enter `'name=value'` manually; `'name='` specifies an empty value. The command reads the module and its enabled scripts after argument substitution and condition filtering. Relative script paths use the module's final URL or local directory, and repeated script URLs are read only once. Other resources, such as Host sets and Map Local files, are not loaded. Scripts are never executed, source maps are not read, and no configuration, script storage, or disk cache is written. Reads use the host network and `HTTP_PROXY` / `HTTPS_PROXY`, with the existing resource limits and timeout budgets. Source syntax is the same as in the table above. A script read failure stops generation without a configuration fragment.

### Storage Isolation Prompts

Isolation settings appear only when syntax analysis recognizes an unshadowed `$persistentStore.read(...)` or `.write(...)` call, including a `"read"` or `"write"` string-literal subscript. Comments, strings, regular expressions, and same-name local bindings do not count. This is evidence of a call expression, not proof that its branch executes. Aliases, dynamic property names, and generated code may remain unconfirmed; `eval`, `with`, or apparent API replacement can also prevent confirmation. Unsupported syntax produces a warning rather than a claim that the script is stateless. `$prefs` and Web Storage are not dae storage interfaces. No confirmed calls means no isolation prompts or generated isolation overrides; existing inheritance remains intact.

When at least one script has a confirmed call, choose a module policy, then optionally select individual scripts:

```text
Module isolation [inherit/isolate/share, Enter=inherit, cancel]: share
Script override [Enter=done, list, <number>, cancel]: list
1  "capture" (http-request) [inherit]
2  "refresh" (cron) [inherit]
Script override [Enter=done, list, <number>, cancel]: 1
Policy for "capture" (inherit from module) [inherit/isolate/share, Enter=inherit, cancel]: isolate
Script override [Enter=done, list, <number>, cancel]:
```

The script list contains only confirmed names, sorted by name. Ambiguity is checked against all scripts, including unconfirmed ones; an ambiguous name cannot receive an individual override. `inherit` removes an override, `isolate` writes `isolate_lan: true`, and `share` writes `isolate_lan: false`. Explicit choices are retained even when they match a parent setting. Revisit a script to change it; Enter keeps its current policy. Enter at the script selector finishes, while `cancel` at an isolation prompt cancels the entire fragment. EOF before completion is an error, not a default answer. The argument stage still treats `cancel` as an ordinary value.

The module policy applies to **every script in the module**, including unconfirmed scripts; filtering only controls the interactive choices. `share` uses the same script state for LAN clients and local execution, potentially sharing cookies and tokens. The command warns when sharing is first selected, but never migrates, merges, or deletes existing data. Local execution remains local. Instance settings are not read or edited: module inheritance uses the instance setting when the fragment is loaded. Manually written descriptors remain available for scripts whose storage use cannot be confirmed statically.

For a module named `accounts`, the selections above generate:

```text
module {
  accounts {
    link: 'file:modules/accounts.sgmodule'
    isolate_lan: false
    script {
      name: 'capture'
      isolate_lan: true
    }
  }
}
```

## Module Conditions and Comments

Supported forms include `#!system`, `#!requirement`, leading `#!REQUIREMENT expression directive`, and trailing `#!REQUIREMENT expression` / `//!REQUIREMENT expression`. Enclose a leading expression containing spaces in double quotes. Comparisons, AND/OR/NOT, parentheses, and BEGINSWITH/ENDSWITH/CONTAINS/LIKE/MATCHES are supported.

In conditions, SYSTEM is `linux`, SYSTEM_VERSION is the kernel version, and DEVICE_MODEL, DEVICE_NAME, and LANGUAGE come from the host. iOS/macOS/tvOS ONLY conditions are not enabled. CORE_VERSION comparisons are ignored rather than emulating a Surge version; compound expressions retain only the remaining conditions, and expressions containing only version conditions are considered satisfied. For example, `CORE_VERSION>=20 OR SYSTEM='iOS'` still depends solely on SYSTEM. Other unknown variables produce a warning and skip the corresponding line or module. A module whose conditions are not satisfied has status `disabled`, with no dependencies loaded or capture rules registered.

Sections support `#`, `;`, and `//` comments. Trailing comment markers must be outside quotes and separated by whitespace. For example:

```ini
[MITM]
hostname = example.com # Host scope
[Rule]
DOMAIN,example.com,DIRECT #!REQUIREMENT SYSTEM='linux'
```

## Host and Module Scope

Modules declare the hosts they process. Put exclusions before wildcard entries:

```ini
[MITM]
hostname = %APPEND% -private.example.com, *.example.com
```

`*`, `?`, and `-` exclusions are supported, with the first matching entry deciding the result. The default HTTPS port is 443; use `example.com:8443` for another port or `example.com:0` for all ports. Plaintext HTTP on port 80 is also processed for matching hosts.

Each module computes its hostname list independently: `%APPEND%` appends, `%INSERT%` prepends, and no marker replaces the list. A connection uses only modules matching its initial host and port; URL/Host rewrites do not activate other modules. Modules without hostname entries execute supported `[Rule]` and `[Host]` entries without requiring a CA. Overlapping modules are processed in declaration order, and only the first matching script runs in each direction.

### DNS Host and IP Destination Rewrites

Domain/wildcard entries in `[Host]` handle DNS. Responses support multiple mixed IPv4/IPv6 addresses, `*`/`?`, aliases, `server:`, `script:`, and `DOMAIN-SET:`/`RULE-SET:`. The first match in module and entry order wins. Aliases trigger another lookup, with cycle and depth limits. DNS scripts use `$domain` and `$done({address|addresses|server|servers, ttl?})`, with only one result form allowed; `$done({})` invokes subsequent handlers.

Static addresses are returned according to the A/AAAA/ANY query type; other types receive an empty response. `server:IP[:port]` redirects the original request. Multiple plain IP servers support concurrent resolution and return a successful response while preserving capture identity; encrypted servers are provided by the optional `dns-router` plugin. On Linux, `system`, `syslib`, and `force-syslib` use dae's internal Go resolver: address lookups support `/etc/hosts`, and default DNS servers come from `/etc/resolv.conf`, overridable with [`global.dns_resolver`](dns.md#internal-dns-server-override). This does not emulate macOS split-domain system resolvers or libc-only NSS. Domain sets and rule sets use module dependency downloads and the global resource cache.

System queries preserve absolute domain names without appending local search domains. When Go address lookups cannot distinguish NXDOMAIN from NODATA, the same internal DNS Dial service obtains a protocol response to preserve the rcode and authority section. Alias responses must match the actual alias query before rewriting.

When a set URL contains `=`, put spaces or tabs around the assignment operator to distinguish it from URL query parameters. For example:

```ini
[Host]
DOMAIN-SET:https://lists.example/domains?token=abc = 192.0.2.1
RULE-SET:https://lists.example/rules?token=abc = server:https://dns.example/query?token=def
```

DNS script budgets include waiting for an execution slot. `$httpClient` preserves the original DNS client's routing identity, supports binary bodies, and uses a connection pool limited to that DNS invocation.

Domain Host entries do not generate DNAT or expand HTTP capture. `use-local-host-item-for-proxy` controls whether an already captured proxy connection retains the static Host DNS IP, defaulting to false; direct connections retain that IP. Literal IP-to-IP mappings generate native destination rules, for example:

```ini
[Host]
192.0.2.1 = 198.51.100.1,198.51.100.2
```

Host-only modules do not require a CA or client MITM enablement. Literal IP mappings use the first match in module and entry order and preserve the original port; subsequent routing uses the rewritten destination. With multiple targets, one is selected randomly per connection. UDP retains the session's target and restores reply source addresses.

Literal IP Host entries and native [rules / DNAT](../../zh/configuration/destination-rules.md) share destination rules, with native rules preceding plugin contributions. Only traffic matching the complete filter enters userspace, and block rules for the new destination still apply. See [DNS](dns.md) for transparent DNS forwarding and persistent domain registration.

Literal IP mappings apply to both direct and proxy connections, take precedence over `dial_target_override`, and do not affect the proxy server's own address. Static DNS entries for domains have a TTL of 60 seconds; system and script results default to 0. When a script returns addresses and a positive TTL, results are cached by effective execution scope, script, domain, and plugin chain. Local execution and scripts with isolation disabled share the local cache; isolated LAN results are separated by trusted MAC, independent of the device's IP or port changes. Cache hits return the remaining TTL. An unknown effective scope or a TTL of 0 bypasses the cache and executes the script every time. Each instance holds at most 4096 entries. Scripts rerun after expiration or changes to plugin instances or order; routing-only reloads retain results. Storage reuses the common bounded LRU, but synthetic results are not mixed with upstream answers.

### Restricting Client Sources

`client_source_address` supports IPv4/IPv6, CIDR, MAC, `all`, and `-` exclusions. Comma-separated entries and repeated fields are concatenated in order, and the first match determines the result. IP and MAC matching are independent. Clients are disabled if the setting is absent or no entry matches; enabling everyone requires an explicit `all`, for example:

```text
client_source_address: '-02:00:00:00:00:10,all'
```

You can also select **On** or **Off** for a device in the **HTTPS Modules** area of the [global page/API](api.md). Device overrides take precedence over configuration; **Router default** clears the override. See the [certificate guide](../../zh/configuration/certificate.md) for installation steps.

Enable only devices that trust the CA. dae does not detect trust or retry with passthrough after a TLS failure. Disabled clients pass through along their original route. An unknown MAC can be matched by IP/CIDR in the configuration.

## Body Rewrites

`[Body Rewrite]` supports request/response regex replacement and jq. Replacement pairs on a line and successive rules execute in order, then pass the result to the script for that direction.

```ini
[Body Rewrite]
http-request ^https://api\.example\.com/ "old" "new"
http-response ^https://api\.example\.com/ "(item)-([0-9]+)" "$1:$2"
http-response-jq ^https://api\.example\.com/ ".enabled = true"
```

Use `http-request-jq` for request-side jq. Regex bodies must be valid UTF-8; `^` / `$` match per line, and replacements may be empty. jq processes one JSON document; empty output or execution failure preserves the previous step's body. Requests using chunked transfer or `Expect: 100-continue` skip body rewriting. Exceeding read or decompression limits returns 413 for requests and replays the original content for responses. Locally synthesized responses do not enter the response rewrite chain.

The Surge plugin performs jq parsing, compilation, JSON decoding, and execution in internal workers launched from the same dae binary, using gojq without an external jq installation. All Surge instances, including old and new instances during reload, share at most four processes. Each process runs one task at a time, with at most 16 additional waiting tasks. After the network body has been read and the instance's `max_concurrent_scripts` slot acquired, body decoding, jq worker queueing, and execution share `script_timeout`. A full queue, timeout, worker exit, or exceeded limit preserves the previous step's body. Cancellation terminates and reaps the worker; later tasks create new workers on demand. Each worker caches at most 32 compiled expressions, each limited to 64 KiB. Body transfer is bounded by `max_body_size`, and returned bodies still count toward the host's shared body budget.

Modules containing jq rules require a writable cgroup v2 memory controller. Each worker's `memory.max` is 128 MiB, the whole pool's limit is 512 MiB, and `memory.swap.max` is 0. Loading verifies these limits and compiles expressions in a constrained process; failure to establish limits causes an error. These resources are not created when jq is unused. Limits cover parsed objects, intermediate evaluation objects, and process overhead. The kernel permits temporary overages in some circumstances, so this is not an instantaneous RSS ceiling. Complex expressions or large bodies can exhaust process memory and preserve the original content even within the body-size limit. Workers and their cgroups are reclaimed when the last instance using jq closes.

## Forwarding and Protocols

When HTTP scope is enabled, only TCP/UDP candidate connections matching a module's positive hostname entries and corresponding ports are captured. Actual hostname matching, exclusions, and client enablement then decide whether to decrypt. Unrelated direct traffic remains on the eBPF kernel fast path. Modules containing scripts, URL Rewrite, or Map Local perform HTTP processing first, then evaluate the final destination in this order: destination rules → flow → module pre-matching rejection → explicit dae rules → ordinary module rules → fallback. A block on the original destination does not preempt these admitted requests; a block on the new destination rejects them. Clients not admitted still use ordinary connection routing.

HTTP forwarding and script `$httpClient` calls share request routing. The original host and port use the intercepted IP, with proxy connections sending the domain according to `dial_target_override`; other destinations are resolved through the system resolver, with destination rules and routing applied independently to each address while preserving client source, interface, and policy. Request-routing modules determine routing after HTTP processing; inspection-only modules preserve the original route. Changes to outbound, node, mark, or actual destination separate connection pools. A 302/307 response tells the client to request the new destination; reject and Map Local can synthesize responses directly.

HTTP/1.1, TLS HTTP/2, and HTTP/3 (QUIC v1/v2) are supported. HTTP/3 automatically uses the existing CA, client settings, and hostname scope. Decryption occurs only when a complete ClientHello includes `h3` in ALPN; other QUIC/UDP traffic remains forwarded. Both the client and upstream sides use HTTP/3, with multiple connections and reconnects supported for the same source/destination/domain. An upstream handshake failure does not automatically retry over TCP. HTTP/3 upstream routing matches UDP rules against the final destination. A block prevents the upstream connection, while a module's local response can still be returned directly.

To reject HTTP/3 upstream connections for a particular destination, add a corresponding rule near the beginning of the existing `routing` section. Whether the client retries over TCP is up to the client. For example:

```text
domain(httpbin.org) && l4proto(udp) && dport(443) -> block
```

Kernel domain capture depends on existing DNS domain-to-IP mappings. Missing mappings do not trigger a catch-all TCP/UDP capture or capture based only on HTTPS ports; otherwise-direct traffic continues through the kernel. Connections already brought into userspace by other rules can still use SNI/Host. Shared IPs may introduce extra candidates, but final matching and ordinary outbound routing remain subject to their respective scopes and domain-verification policies. An unavailable hostname, ECH, or certificate pinning may cause processing to fail. HTTP/2 and HTTP/3 allow cross-host authority reuse on the same port; ordinary forwarding keeps the original ingress destination. TLS HTTP/2 returns 421 for `:scheme=http`; see [request scheme](../../zh/design/mitm-http.md#请求-scheme). HTTP/3 does not currently support cross-address migration, 0-RTT, or WebTransport/CONNECT-UDP. Only H3 Alt-Svc advertisements for the same upstream host and port are retained. WebSocket processing covers only the HTTP/1 handshake.

## Script HTTP Requests

`$httpClient` and basic `fetch` use host routing, normal TLS verification, and the shared body budget. `policy` accepts `DIRECT`, `REJECT`, or a currently loaded dae outbound group name. Groups used only by scripts must be listed in plugin settings as `http_policies: proxy,api`; otherwise, groups not referenced by routing are not loaded. This setting overrides only the outbound for script-initiated requests, preserves destination rules, client identity, and mark, and carries across redirects. Unknown or unavailable groups return errors. `policy-descriptor` and `insecure: true` explicitly fail; `insecure: false` retains normal TLS verification.

Automatic redirects reject HTTPS-to-HTTP downgrades at every hop, including a return to HTTP after an HTTP-to-HTTPS upgrade. Rejections report an error through the original callback or Promise. Cross-domain redirects, direct HTTP requests, and HTTP-to-HTTPS upgrades are allowed. `$httpClient` with `auto-redirect: false` and fetch with `redirect: "manual"` still return the original 30x response.

```javascript
(async () => {
  const response = await fetch("https://api.example.com/data", { policy: "DIRECT" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const data = await response.json();
  $persistentStore.write(JSON.stringify(data), "data");
})().catch(console.error).finally(() => $done());
```

fetch provides Headers, Request, Response, and `text()` / `json()` / `arrayBuffer()` / `bytes()`, with cloning and one-time body consumption. Responses are delivered after full buffering. `timeout` is in seconds and can further constrain the script's remaining budget. Cookies are not sent automatically by default; `credentials: "include"` uses the current script's CookieJar. `redirect: "manual"` returns the actual 30x response, while `"error"` refuses to follow it. `AbortController` and `AbortSignal.abort()` / `timeout()` are supported; cancellation stops only the corresponding request. Without an explicit fetch `timeout`, the remaining script budget applies. Streaming bodies, Blob/FormData, browser CORS, and cache/origin controls are unavailable; unsupported options return errors.

## Execution and Debug Logging

After initialization, each module's load result is logged at `info`. Detailed module status is queried on demand instead of repeatedly printing tables in logs.

Query the current modules while dae is running:

```sh
./dae plugins surge status
```

The query reuses the daemon's status service and does not require `global.api_port`. `disabled` means module conditions are not satisfied; `loaded` means resources are loaded; `cached` means the entire module uses the last complete snapshot; `cached dependencies` means some dependencies use cached content. Loading failures report specific causes, and `debug` shows each module's loaded, failed, or pending progress. Queries after a failed reload still show the old running instance. Load status does not imply that a script has matched or executed.

`IP MAPS` shows the number of IP mapping entries. Inspect actual rewrites in `debug` routing logs: `destination_ip` is the original destination, `destination` is the dial target, and `outbound` is the outbound.

`WARNINGS` counts module parsing, loading, and cache-fallback warnings; the command lists their full text by module below the table. TLS handshake failures and script runtime logs are not included in this column.

`TASKS` counts cron and generic script definitions, also included in the `SCRIPTS` total, without counting multiple execution scopes more than once. `Surge script tasks` displays effective execution scopes: every script always has a local row, and device rows exist only when isolation is enabled. The local row comes first, followed by devices sorted by MAC. `SCOPE` explicitly distinguishes `local`, `device MAC …`, and `unknown`; an empty MAC must not be interpreted as local, and unknown is not an executable task target. Other columns show type, expression, time zone, timeout, current status, and next execution time; generic scripts have no scheduling fields. `Last script runs` lists the latest attempt, duration, result, and run/failure/skip counts for the same scopes. Skips include overlaps during discovery or waiting/running, device revocation, and pre-execution device-query failures. `TRIGGER` / `last_trigger` is `cron` or `http-api`. The JSON field is `details.modules[].tasks`, with explicit `scope: "local"|"device"` on every row and `mac` only for device rows. `./dae plugins status -v` also shows this information.

When LAN targets are needed, the target list refreshes at plugin startup, scheduled deadlines, and manual triggers for a specified MAC. Startup and scheduled discovery are asynchronous, with at most one automatic query in flight; local task admission and dispatch do not wait for it. status/list read only the latest snapshot and perform no device-discovery I/O. Display snapshots do not authorize new device tasks; eligibility is checked again before execution. A failed LAN query neither blocks local execution nor dispatches tasks using stale LAN targets. Known non-busy device rows show `unavailable/device_query_failed`; when there are no device rows, module Warnings report the failure. Running tasks retain their actual state. If a task's eligibility recheck ends because its own budget expires or it is canceled, only that task is recorded as `failed/timeout` or `failed/canceled`; other devices are not marked unavailable. Canceled manual admission and worker shutdown also do not count as discovery failures. Recovery clears discovery warnings without erasing execution history. Devices confirmed removed by a normal snapshot are deleted from the list once they have no ongoing tasks; their counts are not retained as persistent history. LAN targets are not queried when all scripts disable isolation.

States include `unavailable` (LAN target query failed), `pending` (waiting for plugin activation), `ready` (generic can be run manually), `scheduled`, `waiting` (waiting for a shared slot), `running`, `unscheduled` (cron has no computable next time, such as February 31), and `stopped`. Local execution is unaffected by LAN discovery state, and normal local rows remain even when there are no devices. Execution records are created only after bulk LAN discovery finishes and confirms targets. Start/end times and timeouts include shared-slot queueing after admission and the pre-execution eligibility recheck, but not the earlier bulk discovery. `last_error` exposes only categories such as `timeout`, `canceled`, `error`, `device_disabled`, and `device_query_failed`; detailed exceptions are logged. `last_result` is `success`, `failed`, or `skipped`. `skipped` means an admitted task was skipped before execution because its device was revoked or an actual query failure occurred; operation metrics still record skipped when JS never ran. `success` means only that the script called `$done` normally, not that its business operation succeeded.

```sh
journalctl -u dae -f -o cat
```

Download routing, client bypasses, and individual request failures use `debug`; automatic execution steps use `trace`. Degraded behavior, such as forwarding original content after script failure or skipping processing because of a limit, uses `warn`. Normal cancellation and explicit script aborts do not warn. `console.log/info/debug/warn/error` preserve the script's selected level, with log mapped to info, and `$notification.post` logs at info. `global.log_level` filters logs but does not affect recent-notification status records.

The script parameter `enable=false` disables loading and execution of that script. `full-header-mode=true` passes headers as field arrays to preserve duplicate values. `debug=true` rereads local scripts before each run, applying the script type's normal failure behavior if reading fails; it does not provide Surge's request-notes interface. `img-url` and `wake-system` are ignored and logged only at `trace`. Unknown parameters and behavior-affecting warnings still use `warning`, and invalid values for supported parameters still cause loading to fail.

| Log event | Meaning |
| --- | --- |
| `upstream_dial` | Actual outbound, node, mark, and destination used by HTTP forwarding, script requests, or background downloads; includes source for client-originated traffic |
| `mitm_bypass` | Host matched, but the client has not enabled MITM |
| `request_begin` → `script_match` → `script_start` → `script_end` | Request, match, execution, and result |
| `*_rewrite_match` / `map_local_match` | Static rule matched |
| `request_failed` | Surge request processing failed |
| `task_start` / `task_end` | cron/generic script start and end; includes module, script name and type, result, and duration |

At `trace`, Surge request and script events use a structured `event` field and are correlated by `connection_id` and `request_id`. A script event's `scope` reports its effective execution scope, with a MAC only for device scope; shared-mode LAN requests show local. `script_end` includes the script, stage, duration, and outcome. Successful loading does not prove execution, and execution success does not guarantee the intended application effect. If `request_begin` is absent, check client source enablement, hostname, TCP/QUIC, TLS trust, domain-verification policy, and interface binding, in that order. Automatic events do not log URL paths, query parameters, authentication headers, or bodies; content explicitly printed by scripts is not subject to this restriction.

### Recent Notifications

When a script calls `$notification.post(title, subtitle, body)`, the current instance retains **up to 50 notifications per effective execution scope and script** in memory in addition to the info log. Groups are keyed by scope, MAC, module name, script name, and type. HTTP request/response, DNS, cron, and generic scripts are supported. `scope` is explicitly `local`, `device`, or `unknown`, with `mac` only for device scope; local and unknown sources never share a group. This shows the effective execution scope, not the original source: a LAN request with isolation disabled shows local, without implying that its source has been authenticated as local. Ordinary `console.log` output is not included.

Each instance also has a **1 MiB conservative JSON-encoding budget**, including scope and MAC, with text charged at its worst-case escaped length. When exceeded, the oldest record is removed first from the scope-and-script group with the most records; ties remove the oldest record. High-frequency groups shorten their own histories first. If the groups still exceed the overall budget, older individual records are also evicted. As a result, a group may retain fewer than 50 records; verbose/JSON output returns all records within the budget. MACs are not added to Prometheus metric labels.

```sh
dae plugins surge status --instance surge
dae plugins surge status --instance surge --verbose
dae plugins surge status --instance surge --json
dae plugins status -v
```

Text output under `Recent Surge notifications` defaults to **the latest three records per execution scope and script**, newest first, with time, instance/module/script, execution scope and device MAC, type, and body. It reports the hidden count when records are omitted. `--verbose` (`-v`) and `dae plugins status -v` show all retained notifications. Identically named scripts in different instances, scopes, or modules are counted separately.

`--json` always returns all retained records in the instance's `details.notifications`, also available from `plugins[].details.notifications` in `GET /api/status`. The field is omitted when there are no notifications. More than 50 records for the same scope and script evict the oldest records; reload/restart clears them. For example:

```json
{
  "id": 3,
  "created_at": "2026-09-29T09:05:00+08:00",
  "module": "cron_demo",
  "scope": "device",
  "mac": "02:00:00:00:00:50",
  "script": "demo.cron",
  "script_type": "cron",
  "title": "Task completed",
  "subtitle": "Demo notification",
  "body": "This run has completed"
}
```

`id` increases per instance; history and numbering reset on reload/restart and are not written to `$persistentStore`. Module name, script name, title, and subtitle are each limited to 1024 UTF-8 bytes, and the body to 4096 bytes. Overlong values are truncated at character boundaries and return `truncated: true`. Once posted, a notification remains even if the script subsequently fails.

Notification content is text explicitly submitted by scripts, preserves line breaks, and uses existing administrative status-access permissions. The CLI removes terminal control characters for display, while JSON preserves the original text. Additional notification options remain ignored; no system popup or phone push notification is generated.

## Scheduled cron Scripts

The following demonstration module, `modules/cron-demo.sgmodule`, only writes a log:

```ini
[Script]
demo.cron = type=cron,cronexp="5 9 * * *",script-path=cron.js
```

Create `cron.js` in the same directory as the module:

```javascript
console.log("Cron demo: " + $cronexp);
$done();
```

Add this to the Surge instance's `module` section:

```text
cron_demo: 'file:modules/cron-demo.sgmodule'
```

`cronexp` is required. Its five fields are minute, hour, day of month, month, and day of week; the six-field form adds seconds at the beginning. It supports `*`, comma-separated lists, ranges, steps, and English month/weekday names. Weekdays use `0–6`, with Sunday as 0. Scheduling uses the **daemon's local time zone**: for example, `5 9 * * *` runs daily at 09:05, and `*/10 * * * * *` runs every ten seconds. The time zone comes from the daemon's system environment, not the phone.

The next future execution is scheduled after plugin activation. Tasks do not run during module preparation, and startup does not catch up on historical runs. Each scheduled occurrence always executes **once locally**. If the script's effective isolation is enabled, it additionally runs once per MAC for **currently MITM-enabled LAN devices**. With isolation disabled, all sources share local state and the script runs only once locally. LAN eligibility requires host MITM enablement and a ready CA. Explicitly enabled MACs need not be online; `all`, IP, and CIDR entries enumerate only LAN devices known to the host, and explicit device disablement overrides configuration. Local execution does not depend on the device service, LAN targets, MITM enablement, or CA readiness; slow or failed queries do not block local admission or dispatch. While automatic discovery is pending, each script retains only one pending LAN run. Repeated deadlines are coalesced as skipped, without replaying each occurrence; other scripts that become due later use a subsequent fresh query. If multiple deadlines are missed while running, each due task triggers at most once per execution scope, then schedules a future time. When the same task is already waiting/running in the same effective scope, scheduled triggers count as skipped and manual triggers return a conflict. Overlapping executions that finish during discovery are not replayed later; other scopes remain independent. All tasks share `max_concurrent_scripts`, with no separate or priority slots for local execution. The budget starts at actual admission and includes shared-slot queueing, the pre-execution eligibility recheck, JS, and HTTP, but excludes earlier bulk discovery. Tasks inherit `script_timeout` unless the script specifies `timeout`. Reload/stop cancels tasks, automatic discovery, and HTTP requests, then waits for cleanup. New instances reschedule tasks and reset run history and counts.

Device candidates come from MACs in the current MITM policy, published routing and its referenced clientset MACs, and the LAN neighbor table, not from script storage or traffic statistics. Offline clientset members used only for ipset/nftset export and not referenced by routing are not candidates on that basis alone. Candidates without an IP can run only when eligibility is determined without depending on an IP. A device override of On does not require the device to be online. `all` or CIDR cannot enumerate devices the host has never identified and does not trigger active scanning.

The runtime provides `$script.type = "cron"`, `$cronexp`, and the configured `$argument`, without `$request`/`$response`. Scripts must call `$done()`; its return value is ignored. HTTP/DNS/generic scripts in the same instance and effective scope share `$persistentStore`; capture and cron isolation settings must agree. `store: false` disables persistence. Background `$httpClient` uses daemon routing; the selected MAC determines state ownership only, without simulating the device's network source. Cron-only modules need no MITM hostname and add no capture rules; local tasks need no MITM/CA. LAN Cookie capture still requires the hostname, certificate trust, device enablement, and DNS mapping conditions to be satisfied.

`console.log` and `$notification.post` write to daemon logs; the latter also appears in status under [recent notifications](#recent-notifications).

## Manual generic Scripts

`generic` has no automatic trigger and runs only when invoked by name through the CLI/API. Example module `modules/tools.sgmodule`:

```ini
[Script]
demo.tool = type=generic,script-path=tool.js,argument=hello,timeout=10
```

Omitting `type` also means generic; the script still needs a name and `script-path`. Enabled cron/generic task names must be unique within a module. Create `tool.js` in the module's directory:

```javascript
$notification.post("Generic demo", $argument, "Triggered by " + $trigger);
$done();
```

Add `tools: 'file:modules/tools.sgmodule'` to the instance's `module` section, reload, and execute locally with `dae plugins surge run demo.tool --instance surge --module tools`.

The runtime provides `$script.type = "generic"`, `$trigger = "http-api"`, and the configured `$argument`, without type-specific input. Scripts must call `$done()`; manual execution ignores its return value and waits for a timeout if it is not called. Each execution uses an independent VM.

generic and cron share the background executor, effective-scope storage and notifications, daemon-routed HTTP client, and execution slots. Timeouts include queueing. Repeated triggers are rejected while the same task is waiting/running in the same scope. After plugin activation, the local target is idle and `ready`, independent of MITM, CA, or device services; isolated device targets must still meet current MITM eligibility. Stop/reload cancels execution and waits for cleanup. Generic-only modules need no MITM hostname and create no capture rules.

## Manual Triggers

With the daemon running, first list cron and generic scripts that support manual execution, then trigger one using its `SCRIPT` name:

```sh
dae plugins surge list
dae plugins surge list --instance surge --module cron_demo
dae plugins surge list --json
dae plugins surge run demo.cron --instance surge --module cron_demo
dae plugins surge run demo.tool --instance surge --module tools
dae plugins surge run demo.tool --instance surge --module tools --mac 02:00:00:00:00:50
dae plugins surge status --instance surge
```

`list` shows instance, module, script name, scope/device MAC, type, status, and cron expression by effective scope, along with usage guidance. It reads only the daemon's loaded cron/generic task snapshot; HTTP and DNS scripts are not in the manual list. `--instance` and `--module` can be combined as filters. `--json` returns a flat array containing `instance`, `module`, `scope`, optional device `mac`, and task fields, or `[]` when no definitions match. Every definition has a local row; multiple scope rows for the same instance/module/name do not make the name ambiguous.

Waiting or running tasks remain listed, but triggering the same task in the same scope again returns a conflict. An `unscheduled` cron task can still run manually. Quote names containing spaces, for example `run 'Demo task'`.

Omit `--module` when the script name is unique, and omit `--instance` when it is also unique across instances. **Omitting `--mac` always executes once locally** and never automatically selects a sole LAN device. `--mac` is only for isolated scripts and selects a currently MITM-enabled device. Explicitly specifying a MAC when isolation is disabled returns `400` and asks for the MAC to be omitted, rather than silently switching to local execution. The command returns the effective execution scope and run number; the task continues in the daemon, and its result is available through status. In `--json`, `status.scope` identifies the execution scope, with `status.mac` only for device scope. `run` corresponds to this task's `runs` in that scope and is valid only for the current instance lifecycle. Status keeps the latest attempt, and reload resets it. Manual execution does not change the schedule. `$trigger` is `http-api` for manual execution and is not injected for scheduled execution.

The corresponding administrative API is `POST /api/plugins/{instanceID}/scripts/run`. A local request body is `{"module":"tools","script":"demo.tool"}`; device execution adds `"mac":"02:00:00:00:00:50"`. Administrative access and `X-Dae-API: 1` are required. Success returns `202`, a missing script returns `404`, an ambiguous name, invalid MAC, or MAC supplied for a non-isolated script returns `400`, a disabled device or busy task in the same scope returns `409`, and an inactive/stopped worker, unavailable device-discovery service, or canceled/timed-out admission returns `503`. Device admission queries respect cancellation from the request, worker shutdown, and the host drain deadline, with an independent effective script timeout: `script_timeout` by default, overridden by the script's `timeout`. This query does not count toward `runs`, execution history, or the post-admission execution budget. After acceptance, the task remains owned by the worker; completion or cancellation of the HTTP request does not stop it. The API does not accept script text or argument overrides.

## Example

Place [`demo.sgmodule`](../../../examples/surge/demo.sgmodule), [`request.js`](../../../examples/surge/request.js), and [`response.js`](../../../examples/surge/response.js) in `/var/lib/dae/modules/`, then use the first configuration example. From a client that trusts the CA, visit `https://httpbin.org/get`. The request gains `X-Dae-Runtime` and the response gains `dae.runtime`, with a value of `quickjs` or `nodejs` according to the build-time backend. `/dae-redirect` tests a 302 response.

See [supported features](../../zh/configuration/surge-module-support.md) for API coverage, behavior differences, and limitations.
