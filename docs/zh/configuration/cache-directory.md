# 缓存与持久化目录

`DAE_LOCATION_CACHE` 指定可写状态目录，未设置或为空时使用 `/var/lib/dae`。建议使用绝对路径；相对路径以进程工作目录为基准。

`http-file://`、`https-file://` 订阅的持久化副本保存在 `persist.d/名称.sub`。dae 按需创建写入目录，不会为缓存自动创建 `/etc/dae`。

主配置仍由 `-c` 指定，`include` 和订阅 `file:nodes.sub` 相对主配置目录。绝对路径统一使用三个斜线，如 `file:///run/secrets/dae/nodes.sub`，不受缓存目录设置影响；不接受 `file://相对路径`。

绝对订阅路径可跟随符号链接并在启动/重载时重新读取；相对订阅路径限制在配置目录内且拒绝符号链接。文件须为常规文件，权限不允许其他用户访问或组用户写入，例如 `0600`、`0640`、`0400`。本地订阅日志显示路径。`http-file://`、`https-file://` 订阅仍须指定名称，用于 `persist.d/名称.sub`；普通 HTTP(S) 订阅不回退缓存。

## NixOS 与 systemd

主配置可用绝对路径放在只读 Nix store，状态单独保存：

```nix
systemd.services.dae = {
  environment.DAE_LOCATION_CACHE = "/var/lib/dae";
  serviceConfig = {
    StateDirectory = "dae";
    StateDirectoryMode = "0700";
  };
};
```

systemd 会准备 `/var/lib/dae`。改变服务环境后需重启。
