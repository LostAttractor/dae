# MITM 证书

dae 使用本地 CA 为匹配主机签发服务器证书，客户端必须安装并信任该 CA。启动、重载和证书过期都不会自动生成或更换 CA。

## 生成和查看

```sh
sudo dae mitm ca generate
sudo dae mitm ca info
```

默认文件为 `/var/lib/dae/mitm-ca.pem` 和 `mitm-ca.key`，名称 `dae MITM CA`，有效期 3650 天。私钥权限为 `0600`，新建父目录为 `0700`；生成拒绝覆盖现有文件。`info` 只读取公开证书，显示有效期、序列号及 SHA-256 指纹。

`DAE_LOCATION_CACHE` 可更改所有 CA 子命令的默认目录；服务与终端命令需使用同一设置，见[缓存目录](cache-directory.md)。显式 `--cert`、`--key` 和 `export --output` 的相对路径以当前工作目录为基准。例如：

```sh
sudo dae mitm ca generate --cert /var/lib/dae/home.pem \
  --key /var/lib/dae/home.key --name 'Home dae CA' --valid-days 3650
```

在 [MITM 宿主配置](mitm-plugins.md)中填写同一组 `mitm.ca_cert`、`mitm.ca_key`。启用时检查 CA 有效期、密钥匹配和私钥权限，并在启动日志中打印 CA 的 SHA-256 指纹。已有设备信任的 CA 应继续使用原文件，可显式指定其绝对路径；更改目录不需要重新生成证书。

## 为 iPhone / iPad 提供下载

在已有 `global` 段中设置 `api_port: 9080` 并重载，然后从 Safari 打开 `http://192.168.1.1:9080/`，替换为路由器实际局域网 IP。启用 `mitm` 并配置 CA 后，页面的 **HTTPS Modules** 区域提供当前 CA 与设备开关。

1. 将页面指纹与 dae 启动日志或 `dae mitm ca info` 的 SHA-256 指纹核对。
2. 下载 `ca.mobileconfig`。
3. 在「设置 → 通用 → VPN 与设备管理」中安装描述文件。
4. 在「设置 → 通用 → 关于本机 → 证书信任设置」中为该 CA 开启完全信任。
5. 回到下载页面，点击 **Test Certificate**，确认 **CA Acceptance** 显示当前浏览器已接受 CA。
6. 为当前设备开启 MITM，再次测试，确认 **Transparent MITM** 通过。

手动安装不自动获得 TLS 信任，第 4 步不可省略，见 [Apple 官方说明](https://support.apple.com/zh-cn/102390)。停止使用时先关闭该设备的 MITM，再移除描述文件。

设备开关、状态来源、证书下载路径与 API 请求格式统一见[页面/API](api.md)。未知 MAC 的客户端仍可下载证书。

CA 测试复用页面的 `api_port`，MITM 测试使用虚拟 IP 的 443 端口，不增加监听端口。虚拟目标由 `global.api_mitm_test_ipv4` 和 `global.api_mitm_test_ipv6` 指定，其流量须能到达 dae。结果只代表当前浏览器；**Verification incomplete** 表示未能完成验证，需检查安装与完全信任设置，以及流量路径。未开启设备 MITM 时，只验证 CA 接受情况。详见[证书与 MITM 测试](api.md#证书与-mitm-测试)。

## 导出和更换

导出只包含公开证书，默认 PEM 写入标准输出；文件输出拒绝覆盖：

```sh
sudo dae mitm ca export --format pem
sudo dae mitm ca export --format der --output /tmp/dae-ca.cer
sudo dae mitm ca export --format mobileconfig --output /tmp/dae-ca.mobileconfig
```

更换 CA 时使用新的文件路径生成，先在客户端安装并信任新 CA，再更新 `ca_cert`、`ca_key` 并重载。确认成功后移除客户端旧证书并归档或删除旧私钥。若只是移动原文件，保留私钥权限并核对移动前后的指纹一致。
