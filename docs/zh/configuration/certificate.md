# 本地 CA 与客户端证书

dae 的本地 CA 由 daemon 管理，API HTTPS 与透明 MITM 共用同一证书身份。API 不依赖 MITM：只设置 `api.listen`，同一端口就同时提供 HTTP 和 HTTPS 页面及完整 API。

## 自动初始化与持久化

默认无需配置证书路径。daemon 准备配置时，若未指定证书且托管目录不存在，会自动生成自签名根 CA；此行为不依赖 TCP API 或 `mitm.enabled`，Unix API 也可导出公开证书：

| 内容 | 默认值 |
| --- | --- |
| 托管目录 | `/var/lib/dae/pki`，权限 `0700` |
| 公开证书 | `ca.pem`，权限 `0644` |
| 私钥 | `ca.key`，权限 `0600` |
| 名称与有效期 | `dae Local CA`，3650 天 |

`DAE_LOCATION_CACHE` 更改基目录，托管目录始终位于其 `pki` 子目录。启动、重载及 MITM 开关变化复用同一 CA；关闭 TCP API 或 MITM 不会删除或重新生成 CA。生成以完整目录原子发布，并发初始化也只保留一份身份。

已有托管目录中的证书缺失、损坏、过期、私钥权限错误或密钥不匹配时，启动或重载报错，不会自动换 CA。重载失败保留已运行的配置。应恢复原文件或显式配置新的 CA；整个 `pki` 目录及私钥必须备份，不能当作临时缓存删除。日志记录已接受 CA 的 SHA-256 指纹。

自动生成只解决服务器证书来源，客户端仍须安装并信任公开 CA。私钥始终留在 dae 主机上。

API HTTPS 的管理叶证书与私钥另外按 CA 指纹和路由器 IP 保存在 `/var/lib/dae/api-tls` 下，同样受 `DAE_LOCATION_CACHE` 控制。每个身份使用一个权限为 `0600` 的 PEM 文件原子保存；有效期内的访问、重启和重载复用相同证书和密钥。管理叶证书有效期为 90 天，且不超过 CA 有效期；仅文件缺失或证书到期时签发并保存。现有文件损坏、密钥不匹配或权限不安全时拒绝加载，不静默换证。

证书信任测试另行签发临时叶证书和新密钥，仅保存在内存中。挑战期限为一分钟；临时证书另留五分钟时钟偏差余量，且不超过 CA 到期时间，不延长挑战期限。测试期间仅发起源 IP 到该路由器 IP 的新 TLS 连接使用挑战证书；证明成功后消费挑战，未完成的挑战到期后失效。该地址对没有剩余挑战后，新连接恢复原管理证书。共享源 IP 的客户端会共享这段临时选择；测试不会改写管理证书文件，重启会丢弃所有临时挑战。MITM 的短期叶证书仍使用独立内存缓存。

## 指定 CA 与命令

需要使用已有 CA 时，在顶层配置：

```text
certificate {
  ca_cert: '/srv/dae/home.pem'
  ca_key: '/srv/dae/home.key'
}
```

两条路径必须同时填写或同时留空；相对路径以 `DAE_LOCATION_CACHE` 为基准。显式路径只读取并校验证书和私钥，缺失时不会生成，也不会回退到托管 CA。

```sh
sudo dae ca info
sudo dae ca export --format pem
sudo dae ca export --format der --output /tmp/dae-ca.cer
sudo dae ca export --format mobileconfig --output /tmp/dae-ca.mobileconfig
```

`info` 只读取公开证书，显示有效期、序列号及 SHA-256 指纹。`export` 只导出公开证书，默认 PEM 写入标准输出，文件输出拒绝覆盖。命令默认访问托管目录；服务和终端应使用相同的 `DAE_LOCATION_CACHE`，见[缓存目录](cache-directory.md)。`info` 和 `export` 可通过 `--cert` 选择其他公开证书。

也可在首次启动前用 `sudo dae ca generate` 预生成托管 CA，或同时指定两个路径生成独立 CA：

```sh
sudo dae ca generate --cert /srv/dae/home.pem \
  --key /srv/dae/home.key --name 'Home dae CA' --valid-days 3650
```

生成拒绝覆盖已有文件或托管目录。CLI 显式路径相对于当前工作目录。更换 CA 时，先生成至新的路径并在客户端安装、信任，再更新 `certificate` 段并重载。新身份发布后，旧 TLS 连接不能用于访问新 CA 元数据；相同 CA 的普通重载保留 HTTPS 连接。确认成功后移除客户端旧证书并归档或删除旧私钥。

## 为 iPhone / iPad 提供下载

配置 `global { lan_interface: br-lan }` 和 `api { listen: 9080 allow_lan_anonymous: true }` 并重载；接口名替换为实际 LAN 接口。然后从 Safari 打开 `http://192.168.1.1:9080/`，替换为路由器实际局域网 IP。原生 API 必须以 IP 直连，裸端口必须配置 LAN 接口 pattern；暂时无匹配接口不会回退为全部地址。无需开启 MITM，页面的 **Certificate & browser verification** 区域即可提供下载和 HTTPS 验证。HTTP 页面仅作匿名安装引导，不能输入 API key；未开启匿名访问时先通过本地 Unix API 导出公开 CA 并可信分发。

1. 将页面指纹与 dae 启动日志或 `dae ca info` 的 SHA-256 指纹核对。
2. 在 **Download** 菜单中选择 **Configuration profile**，下载 `ca.mobileconfig`。
3. 在「设置 → 通用 → VPN 与设备管理」中安装描述文件。
4. 在「设置 → 通用 → 关于本机 → 证书信任设置」中为该 CA 开启完全信任。
5. 回到页面点击 **Test certificate**，确认 **CA trust** 显示 **CA trusted by this browser**，之后可使用 `https://192.168.1.1:9080/`。
6. 如需透明 MITM，在 daemon 启用 MITM 后将当前设备的 **HTTPS Modules** 设为 **On**，页面会自动再次测试，并显示 **HTTPS interception** 结果。

手动安装不自动获得 TLS 信任，第 4 步不可省略，见 [Apple 官方说明](https://support.apple.com/zh-cn/102390)。停止使用时先关闭该设备的 MITM，再移除描述文件。

通过 HTTPS 反代访问时仍可用 key/Cookie 下载 CA，但自身设备与浏览器 CA/MITM 验证不可用；验证须回到原生 API IP 直连。浏览器信任反代页面证书、代理验证 dae CA、浏览器信任 dae CA 是三个不同事实，不能以代理的上游 TLS 握手代替浏览器验证。开发模式不额外隐藏验证入口，是否可用取决于实际直连能力及鉴权。

HTTPS 登录会话使用 `__Host-dae-session` HttpOnly Cookie；HTTP 引导页面不会使用它登录。同一主机名/IP 的 Cookie 不按端口隔离，独立管理页面建议使用专用主机名并按[同源 HTTPS 反代示例](api-client.md#同源-https-反向代理)部署。

测试会为发起源 IP 到该路由器 IP 的连接临时提供新签发的挑战证书，并要求新 TLS 握手，先前点击“接受风险”不会被当作 CA 信任；无需先访问 HTTPS，直接在 HTTP 安装页测试即可。持久化管理证书、CA 和 MITM 证书均不改变；挑战证明成功或过期后移除临时证书，该地址对没有剩余挑战时恢复管理证书。仅靠管理证书例外访问 HTTPS 的新连接在挑战有效期内可能被拒绝，此时可回到 HTTP 安装页。测试只验证当前浏览器，不检查系统或其他应用的信任库；没有 MAC 或未开启 MITM 时仍可测试。透明 MITM 另外通过虚拟 IP:443 的短期挑战确认真实捕获和解密；详见[证书与 MITM 测试](api.md#证书与-mitm-测试)。
