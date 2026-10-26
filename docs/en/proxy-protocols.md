# Proxy Protocols

> **Note**: dae currently supports the following proxy protocols

Each `node` entry must contain one share link. Compose proxy paths with group path expressions as documented in [Routing](configuration/routing.md).

- [x] HTTP(S), naiveproxy

  ```
  https://[[user:]pass@]hostname:port/
  ```

- [x] Socks
  - [x] Socks4
  - [x] Socks4a
  - [x] Socks5

  ```
  socks4://[[user:]pass@]hostname:port/
  socks5://[[user:]pass@]hostname:port/
  ```

- [x] VMess(AEAD, alterID=0) / VLESS
  - [x] TCP
  - [x] WS
  - [x] TLS
    - [x] Reality
  - [x] gRPC
  - [x] Meek
  - [x] HTTPUpgrade

  [v2rayN URI Schema](https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2))

  [DuckSoft URI Schema](https://github.com/XTLS/Xray-core/discussions/716)

  REALITY `spx` crawler parameters accept a nonnegative integer or an ordered range. Limits are 4096 for `p` (padding bytes), 8 for `c` (concurrency) and `t` (requests per worker), 60000 for `i` (interval milliseconds), and 5000 for `r` (return delay milliseconds). Omitted values default to zero; malformed, duplicate, or out-of-range parameters reject node construction.

  Camouflage crawling runs at most one task per node and eight across the process. Each task lasts at most ten seconds and reads response bodies up to 1 MiB. Discovered paths live only for that task: at most 256 paths and 256 KiB in total, with a 4096-byte limit on each path and the initial `spx`. Completion, timeout, or node release closes the connection.

- [x] Shadowsocks
  - [x] AEAD Ciphers
  - [x] Stream Ciphers
  - [x] simple-obfs
  - [ ] v2ray-plugin
    - [x] Websocket (+TLS)

  [SIP002](https://shadowsocks.org/doc/sip002.html)

  [SIP008](https://shadowsocks.org/doc/sip008.html)

  An unsupported SIP003 plugin rejects node construction. Plain Shadowsocks transport is used only when no plugin is specified.

  SIP002 links describe only standard Shadowsocks connection information. Keep the link unchanged and use node options for dae-specific features:

  ```shell
  node {
    hk: 'ss://LINK' [multiplex: smux, multiplex_max_connections: 10]
  }
  ```

  For subscription nodes, use an expanded subscription descriptor and match the parsed node name, protocol, or original link:

  ```shell
  subscription {
    my_sub {
      link: 'https://example.com/subscription'
      option {
        filter: protocol(shadowsocks) && name(regex: '^HK') [multiplex: smux]
        filter: name(HK-legacy) [multiplex: off]
      }
    }
  }
  ```

  `multiplex` enables sing-box-compatible multiplexing (sing-mux): `smux` and `yamux` multiplex both TCP and UDP, `smux-udp-passthrough` and `yamux-udp-passthrough` multiplex TCP while keeping UDP on the underlying proxy protocol, and `off` explicitly disables multiplexing. sing-box servers accept both protocols once `multiplex.enabled` is set, with no further server configuration.

  smux shares one 4 MiB receive buffer per session, so a stream whose reader stalls, such as a paused video, stops every other stream of that session. Sending is shared among streams by bytes, as fq_codel shares a link: a stream that just turned busy goes first, so a game's or DNS datagram is preferred at the next schedulable frame boundary rather than behind a bulk upload's queue. A stream queues up to 64 KiB of actual buffer capacity, filling existing frames first, and only its own writer waits for room. In-flight batches retain ownership and accounting of their buffers. Batches fill across frame boundaries, but a started frame must finish before another frame starts. A closed stream retains send ownership until FIN is written; a session with 64 closed streams still draining refuses new opens without dropping accepted tails. Only a nonempty queue waits at the gate. The gate wait and the following carrier write share one `netproxy.DialTimeout` deadline; expiry terminates the session. Each carrier write waits until the carrier's TCP socket holds less than half its unsent limit, which lasts about 6 ms at the carrier's rate (at least 16 KiB, at most half the socket's send buffer, and higher while dae's writer rather than the network sets the pace), so that what goes next is chosen above the socket rather than queued behind a long kernel queue. Lowering the limit cannot retract bytes already queued under the previous limit; those must drain first. This needs the TCP socket under the carrier, which dae finds through Shadowsocks, Shadowsocks 2022, TLS and simple-obfs, but not through transports such as WebSocket or gRPC. When both ends negotiate MPTCP, the limit applies to the MPTCP socket only: its subflows queue what it hands them without one. UDP datagrams never wait for the connection: each is queued, up to 64 KiB per UDP socket (smux stream) and 256 KiB per session; beyond that the oldest datagram of the stream, or of the session's fattest stream, is dropped, so that a stream that queued nothing always gets its datagram in. A datagram stream whose datagrams keep waiting over 5 ms, beyond what its fair share of the session explains, is thinned by CoDel. Every drop is counted with the other UDP drops, and the wait of every datagram sent is recorded (see [metrics](configuration/metrics.md)). Replies go to the client straight from the session's receive loop; a reply that cannot be sent at once, such as the first from a new address, waits with the later replies of its UDP socket in a queue of up to 128, beyond which replies are dropped and counted likewise. yamux has per-stream flow control and streams do not hold each other back. A yamux stream's download window grows up to 8 MiB while it is read quickly, about 330 Mbit/s at 100 ms RTT or 170 Mbit/s at 200 ms. The streams of one session share 32 MiB of window growth, enough for 4 streams at full window, and a stream keeps its growth until it closes; a closed stream is reset if the server has not closed it within 5 seconds. A session with less than one full window of growth left counts as loaded, so new streams prefer other sessions. When every session has reached that point and `multiplex_max_connections` is used up, new streams stay at the initial 256 KiB window, about 20 Mbit/s at 100 ms RTT or 10 Mbit/s at 200 ms, until grown streams close. Uploads are limited by the server's fixed 256 KiB window, about 20 Mbit/s per stream at 100 ms RTT. yamux sessions also exchange keepalive pings every 30 seconds.

  Each multiplexed node keeps one session (an independent outer TCP connection) and opens more on demand, up to 4 by default; `multiplex_max_connections` can set the limit from 1 to 16. Sessions are kept apart by lane, so that each kind of traffic shares an outer connection only with its own: interactive UDP (games, DNS, calls), QUIC (UDP sniffed as QUIC) and TCP. A loss on the outer connection stalls all its streams for a round trip, and a TCP reader that stalls stops the whole smux session; a game sharing neither feels neither. A session takes the lane of its first user stream. A smux session becomes a spare only after its last stream ends and queued and in-flight data and FIN drain. A reserved connectivity check not yet queued is not a clean spare either; a busy untagged session is only a last-resort fallback. The drain event feeds the existing recovery coordinator rather than a separate recovery loop. A lane without a session takes the spare, and another spare is requested at once, so that a lane that starts later still finds a clean session; the default 4 is one session per lane and a spare. With fewer sessions, or before the spare is replaced, a stream uses another lane's session: interactive UDP prefers QUIC's to TCP's, and the other lanes use the interactive session only when nothing else is left; such a stream stays where it was placed. A lane whose sessions all carry at least 4 user streams, or, with yamux or a stalled smux session, cannot take more, requests another session only from the positions left after one for each lane without a session and one for a missing spare, one request at a time; a TCP-only node thus uses one TCP session at the default 4, two at 5 and three at 6. Connectivity checks use the interactive session, else the spare, never change a lane, neither add sessions nor count towards the 4 streams. Extra sessions without user streams for 60 seconds are closed while another session is connected, except the last spare while any session has a lane, and an extra session lost while idle is not re-established unless it is the last spare while a lane is active. Multiple sessions give concurrent connections separate TCP congestion control, but do not increase the throughput of one inner TCP connection.

- [x] ShadowsocksR

- [x] Trojan
  - [x] Trojan-gfw
  - [x] Trojan-go

  [trojan/trojan-go URI Schema](https://p4gefau1t.github.io/trojan-go/developer/url)

- [x] Tuic (v5)

  [Tuic URI Schema](https://github.com/daeuniverse/dae/discussions/182)

- [x] Juicity

  [Juicity URI Schema](https://github.com/juicity/juicity?tab=readme-ov-file#link-format)

- [x] Hysteria2

  [Hysteria2 URI Schema](https://v2.hysteria.network/docs/developers/URI-Scheme)

- [x] AnyTLS

  [AnyTLS URI Schema](https://github.com/anytls/anytls-go/blob/main/docs/uri_scheme.md)

- [x] Group proxy paths

  Compose protocols with group path expressions; share-link chain URIs are not supported.

For other requirements, one way to expand protocol support is by using external proxy programs. Below is an example of using the external naiveproxy.

Although dae and other proxy programs support the HTTPS protocol, using them does not utilize the chromium networking stack, which weakens the camouflage effect of naiveproxy. Therefore, using an external naiveproxy program is recommended.

1. Start naiveproxy:

   The example uses naiveproxy to open an HTTP listening port. Note that HTTP proxy does not support proxying UDP traffic, so if you are using an external proxy program, it is advisable to prioritize using the socks5 port.

   ```bash
   naiveproxy --listen=http://127.0.0.1:1090 --proxy=https://yourlink
   ```

2. In the section of dae's configuration related to nodes, add the following line: `http://127.0.0.1:1090`, and remember to use this node in the group you are using.

3. If you have bound the WAN interface, meaning you have filled in the `global.wan_interface` field, add the following control in `rules` and put the `direct` rule near the top of `routing` to prevent traffic from flowing back to dae after passing through naiveproxy, causing a loop:

   ```shell
   routing {
       rules {
           pname(naiveproxy) -> must
       }
       pname(naiveproxy) -> direct
       # Other routes and fallback ...
   }
   ```

   Here, `pname` refers to the process name. You can determine the process name of naiveproxy by examining the command used to start it, running the `ps -ef` command at runtime, or observing the dae logs. `must` skips automatic DNS interception, while the early `direct` rule selects direct forwarding. Avoid explicit `bump`, MITM or DNAT capture for this process to keep its traffic in the kernel.

   Users who only bind the LAN interface do not need to perform this step.
