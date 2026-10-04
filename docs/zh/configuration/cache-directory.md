# 缓存与持久化目录

`DAE_LOCATION_CACHE` 指定可写状态目录，未设置或为空时使用 `/var/lib/dae`。建议使用绝对路径；相对路径以进程工作目录为基准。

| 内容 | 默认位置 |
| --- | --- |
| CA 命令默认文件 | `/var/lib/dae/mitm-ca.pem`、`mitm-ca.key` |
| [页面/API](api.md) 的设备集合、selector 选择与 MITM 开关 | `/var/lib/dae/runtime-state.json` |
| Surge `file:相对路径` 模块、相对 `ca_cert`、`ca_key`、`store` | 相对于 `/var/lib/dae` |
| HTTP(S) 模块及依赖缓存 | `/var/lib/dae/resources/surge/` |
| HTTP(S) 订阅缓存 | `/var/lib/dae/resources/subscriptions/` |

目录包含 CA 私钥和脚本存储，不能整体当作临时缓存清空。dae 按需创建写入目录，不会为缓存自动创建 `/etc/dae`；CA 只由显式 [generate 命令](mitm-certificate.md)生成。已有文件可继续用绝对路径引用，无需重新生成 CA。

主配置仍由 `-c` 指定，`include` 和订阅 `file:nodes.sub` 相对主配置目录。模块 `file:modules/demo.sgmodule` 则相对 `DAE_LOCATION_CACHE`。绝对路径统一使用三个斜线，如 `file:///run/secrets/dae/nodes.sub`，不受这些目录设置影响；不接受 `file://相对路径`。

绝对订阅路径可跟随符号链接并在启动/重载时重新读取；相对订阅路径限制在配置目录内且拒绝符号链接。文件须为常规文件，权限不允许其他用户访问或组用户写入，例如 `0600`、`0640`、`0400`。本地订阅日志显示路径。

## 全局资源缓存

```text
global {
  resource_cache: true
}
```

`resource_cache` 默认开启，统一控制 daemon 加载 HTTP/HTTPS 订阅、Surge 模块及远程脚本、Host 集合和 Map Local 依赖时的磁盘缓存。启动/重载时优先联网，下载或内容校验失败才回退；缓存没有自动过期时间。设为 `false` 后不读取、写入或清理资源缓存，已有文件保留。本地文件始终读取当前内容。此设置不影响脚本 `$persistentStore`、运行中的 `$httpClient` 请求或流量转发。

订阅下载失败、内容无法解析或没有可用节点时，会读取并验证已有副本。这包括 HTTP 200 响应正文实际是超时、限频提示或错误页面的情况。只有新内容解析成功且至少有一个节点通过验证后才更新副本，错误响应不会覆盖旧缓存。回退成功会记录 `Subscription update failed; using cached nodes`；没有可用副本时，该订阅会被跳过。联网刷新预算耗尽仍可回退，调用方取消则停止加载。

订阅缓存按规范化完整 URL 的哈希命名，与订阅名称无关，匿名订阅也可缓存；同名不同 URL 不会混用，URL 或访问令牌改变会使用新的缓存。订阅联网刷新预算为启动两分钟、重载 30 秒；启用缓存时额外保留 5 秒用于缓存读取与节点校验，整个加载过程仍有超时限制。订阅加载结束会清理已不在配置中的订阅快照；关闭缓存时不清理。

模块内相对脚本、Map Local 文件保持 `script-path=request.js` 等 Surge 写法，以模块目录或最终 HTTP(S) URL 为基准；本地模块也可用 `file:` 指定依赖。CLI 显式 `--cert`、`--key`、`export --output` 相对工作目录。`plugins.<实例 ID>.store` 未填写时只保存在内存。

模块和远程依赖全部读取、校验成功后原子保存完整快照，刷新失败时整体回退，避免混用不同版本。本地模块始终使用当前文件；回退时只从上次完整快照读取当前模块引用的远程依赖，新增但未缓存的依赖仍会失败。模块缓存按规范化来源 URL/路径和显式参数的哈希保存，不按别名或实例 ID；相同来源与参数可复用，不同参数组合使用独立缓存。

模块读取失败时，若未启用缓存或没有可用缓存，则新配置加载失败；订阅和模块的缓存写入失败只警告，不丢弃已验证内容。缓存文件权限为 `0600`，新建目录为 `0700`。模块列表共用两分钟刷新预算。完整缓存不验证 JavaScript 执行，错误脚本可能保存且不会因运行失败自动回退。

## NixOS 与 systemd

主配置和模块可用绝对路径放在只读 Nix store，状态单独保存：

```nix
systemd.services.dae = {
  environment.DAE_LOCATION_CACHE = "/var/lib/dae";
  serviceConfig = {
    StateDirectory = "dae";
    StateDirectoryMode = "0700";
  };
};
```

systemd 会准备 `/var/lib/dae`。自定义目录时，终端命令也需指定相同环境变量，例如 `sudo env DAE_LOCATION_CACHE=/srv/dae dae mitm ca info`；服务环境不会自动传入终端，改变服务环境后需重启。参见 [NixOS dae 模块](https://github.com/NixOS/nixpkgs/blob/master/nixos/modules/services/networking/dae.nix)、[systemd 目录设置](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#RuntimeDirectory=)和[完整 Surge 配置](surge-module.md#配置与运行)。
