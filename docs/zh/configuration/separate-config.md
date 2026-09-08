# 拆分配置文件

通过 `include` 可以分别维护节点、DNS 和路由配置。路由策略通过有序的 `use` 组合共享的 `rule_set` 片段，规则集也可以继续引用其他规则集。

相对 include 路径始终基于入口配置文件所在目录解析，包括被包含文件中的 include。绝对路径按原样使用，但所有被包含文件仍须位于入口配置目录之下。

## 目录结构

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

## 配置文件

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

## 组合与优先级

- 每个文件保留 `routing { ... }` 外层。每个命名片段和策略在合并后的配置中只能声明一次；大型策略通过 `use` 组合不同片段。
- 引用可以先于声明。规则和 `use` 的顺序决定匹配顺序，文件名不能替代这个顺序。`use: a, b` 等价于连续引用 a 和 b，循环引用会报错。
- 片段不能含 fallback，每个策略必须声明一个 fallback。示例中 `main` 和 `lan` 复用 `regional` 的规则，分别使用 `my_group` 和 `direct` 作为 fallback。
- `default: main` 选择默认策略；接口表独立选择完整策略。`wg0` 使用 `tunnel`，只执行 `base` 后回退到 `my_group`。同一策略可供多个接口和默认路由共同选择。
- 接口名必须精确且不能重复绑定。通过 `global.lan_interface` / `global.wan_interface` 配置流量接管，接口路由绑定不会自动接管设备。
- 单一默认策略也可直接在 `routing` 中写规则、use 和 fallback，并与片段及命名策略声明共存；此时省略 `default: 策略名`。

MITM 插件、原生 DNAT 和 Surge Host 所需的内部捕获片段由所有策略自动共享，无需重复写 `control_plane_routing` 或添加 `use`。`rules { ... -> dnat(ip) }` 和 `mitm { ... }` 仍是顶层配置。

规则与模块优先级见[路由配置](routing.md)。替换示例节点、订阅地址和接口名后启动：

```sh
dae run -c /etc/dae/config.dae
```
