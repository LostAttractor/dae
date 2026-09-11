# Separate Configuration Files

Use `include` to keep nodes, DNS and routing in separate files. Routing policies can compose shared `rule_set` fragments with ordered `use` statements, including nested references.

Relative include paths are resolved from the directory containing the entry configuration file, even inside an included file. Absolute paths are used as-is, but every included file must remain below the entry configuration directory.

## Directory layout

```text
/etc/dae/
├── config.dae
└── config.d/
    ├── dns.dae
    ├── node.dae
    ├── 10-base.dae
    ├── 20-regional.dae
    ├── 30-policies.dae
    └── 40-interfaces.dae
```

## Configuration files

`config.dae`:

```shell
# config.dae
include {
    config.d/*.dae
}

global {
    tproxy_port: 12345
    log_level: warn
    lan_interface: br-lan, wg0
    wan_interface: auto
    auto_config_kernel_parameter: true
    dial_target_override: true
    reroute_mode: while_needed
}
```

`config.d/dns.dae`:

```shell
# config.d/dns.dae
dns {
    upstream {
        alidns: 'udp://dns.alidns.com:53'
        googledns: 'tcp+udp://dns.google:53'
    }
    routing {
        request {
            qname(geosite:category-ads-all) -> reject
            fallback: alidns
        }
        response {
            upstream(googledns) -> accept
            !qname(geosite:cn) && ip(geoip:private) -> googledns
            fallback: accept
        }
    }
}
```

`config.d/node.dae`:

```shell
# config.d/node.dae
node {
    node1: 'socks5://127.0.0.1:1080'
    node2: 'socks5://127.0.0.1:1081'
}
subscription {
    my_sub: 'https://www.example.com/subscription/link'
}
group {
    my_group {
        filter: subtag(my_sub) && !name(keyword: 'ExpireAt:')
        policy: min_moving_avg
    }
    local_entry {
        filter: name(node1)
    }
    local_group {
        group(local_entry) -> node(node2)
        policy: fixed(0)
    }
}
```

`config.d/10-base.dae`:

```shell
# config.d/10-base.dae
routing {
    rule_set {
        base {
            pname(NetworkManager) -> direct
            dip(224.0.0.0/3, 'ff00::/8') -> direct
            dip(geoip:private) -> direct
        }
    }
}
```

`config.d/20-regional.dae`:

```shell
# config.d/20-regional.dae
routing {
    rule_set {
        regional {
            use: base
            domain(geosite:openai) -> local_group
            dip(geoip:cn) -> direct
            domain(geosite:cn) -> direct
        }
    }
}
```

`config.d/30-policies.dae`:

```shell
# config.d/30-policies.dae
routing {
    policy {
        main {
            use: regional
            fallback: my_group
        }
        lan {
            use: regional
            fallback: direct
        }
        tunnel {
            use: base
            fallback: my_group
        }
    }
}
```

`config.d/40-interfaces.dae`:

```shell
# config.d/40-interfaces.dae
routing {
    default: main
    interface {
        br-lan: lan
        wg0: tunnel
    }
}
```

## Composition and precedence

- Keep a `routing { ... }` wrapper in each file. Declare each named fragment and policy once across the merged configuration; compose large policies using `use`.
- References may precede declarations. Rules and uses determine matching order, independently of filenames. `use: a, b` references a then b; cycles are rejected.
- Fragments cannot contain fallback. Each policy declares exactly one fallback. Here, `main` and `lan` share the rules in `regional`, with `my_group` and `direct` as their respective fallbacks.
- `default: main` selects the default policy. Interface bindings independently select complete policies. `wg0` selects `tunnel`, which runs only `base` before falling back to `my_group`. Several interfaces and the default may select the same policy.
- Interface names are exact and cannot be bound twice. Configure traffic capture with `global.lan_interface` / `global.wan_interface`; routing bindings alone do not attach dae to devices.
- A single default policy may instead write rules, uses and fallback directly inside `routing`, alongside fragment and named policy declarations. In that form, omit `default: policy_name`.

HTTP plugins, native DNAT rules and literal-IP Surge Host mappings automatically share their internal capture fragment across all policies. No repeated `control_plane_routing` rules or explicit `use` are needed. Keep `rules { ... -> dnat(ip) }`, `plugins { ... }` and the HTTP/TLS settings in `mitm { ... }` at the top level. Domain Host entries handle DNS without creating DNAT rules.

See [routing](routing.md) for matching and module precedence. After replacing the sample nodes, subscription URL and interface names, start dae with:

```sh
dae run -c /etc/dae/config.dae
```
