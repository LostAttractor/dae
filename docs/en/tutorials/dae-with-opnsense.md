# dae with OPNsense: Best Practices

This tutorial shows how to use dae with OPNsense in a bypass way. dae is installed on another Linux system and is connected to OPNsense via Ethernet (physical connection, Linux bridge, or SR-IOV).

## Interfaces

You should assign an address for the interface between dae and OPN that is in a different subnet from OPN's LAN. If we call this interface wan_proxy, the configuration is as follows:

```
OPN LAN: 192.168.1.1/24
OPN wan_proxy: 192.168.2.2 Gateway Auto Detect
dae enp1s0: 192.168.2.1 Gateway 192.168.2.2
```

## Traffic Splitting

1. Configure the GeoIP list

   > Add it in `Firewall: Aliases: GeoIP Settings`, refer to the [OPN documentation](https://docs.opnsense.org/manual/how-tos/maxmind_geo_ip.html).

2. Configure GeoIP alias

   > Add an alias named proxyip in `Firewall: Aliases: Aliases`, select GeoIP type, and choose China in the displayed region Asia(or your own country).

3. Add additional IP address list (optional)

   > Add an alias named proxyip_ex in `Firewall: Aliases: Aliases`, select URL Table type, you can add a link to an IP list maintained by others, the file content is an IP address represented by CIDR per line.

4. Configure reserved address alias

   > Add an alias named \_\_private_network in `Firewall: Aliases: Aliases`, select Network type, add all reserved addresses (or only add the reserved addresses used in your network), refer to [Reserved IP Addresses](https://www.wikiwand.com/zh-hant/保留IP地址).

5. Aggregate the above aliases

   > Add an alias named proxyroute in `Firewall: Aliases: Aliases`, select Network group type, select proxyip, proxyip_ex (if any), \_\_private_network and the system built-in \_\_lo0_network alias, and aggregate them.

6. Add gateway

   > Add a gateway named proxy in `System: Gateways: Single`, select the interface wan_proxy between dae, the IP is the IP of dae, according to the interface example above, fill in 192.168.2.1 here, the priority must be lower than the default gateway, such as the default gateway set to 254, set this to 255.

7. Traffic splitting rules

   > Add a rule in `Firewall: Rules: Floating`, configure as follows:

   | Item | Configuration |
   | - | - |
   | Action | Pass |
   | Quick | √ |
   | Interface | LAN |
   | Direction | in |
   | TCP/IP Version | IPv4 |
   | Protocol | TCP/UDP |
   | Destination/Invert | √ |
   | Destination | proxyroute |
   | Gateway | proxy |

   > In addition, you can exclude LAN devices through Source/Invert, so their traffic will not be passed to dae.

8. Allow dae traffic to enter OPN

   > Create a new rule in `Firewall: Rules: wan_proxy`, keep all defaults and save.

9. OPN's own proxy (optional)

   > If you need to route some of OPN's own traffic through the proxy, such as using Google Drive to backup configurations, it is recommended to add a static route rule in `System: Routes: Configuration`, set the gateway for the IP segment that needs to be proxied to proxy. It is not recommended to handle WAN traffic in floating rules, which may cause loops.

## dae related configuration

This section does not involve the content of the dae configuration file, but only gives how to configure DNS requests to pass through dae, and solutions to the common problem that the proxy is normal and the direct connection is not working. For `routing` rules, please refer to the dae documentation.

dae learns domain-IP evidence from the DNS replies it relays (dae does not listen on port 53; DNS requests only need to be routed through it). Domain rules and the verification of sniffed domains rely on this evidence, so DNS requests should pass through dae when you split traffic by domain; see [DNS](../configuration/dns.md). Without domain rules, the following configuration can be ignored.

1. DNS forwarding configuration
   > Set in `Services: Unbound DNS: Query Forwarding`, forward DNS requests to the specified server, such as configuring OpenDNS's 208.67.222.222. The next step requires setting a static route rule, setting the gateway of this address to dae, so do not use the DNS issued by your upstream, so that you can normally use dig or nslookup to query the DNS server issued by the upstream for testing when troubleshooting DNS problems.

2. Static route configuration
   > Add a static route rule in `System: Routes: Configuration`, set the network to 208.67.222.222/32, and set the gateway to proxy.

After the above configuration, DNS requests pass through dae, which relays them to their original server; the optional `dns-router` plugin can send them to another upstream.

In addition, since dae does not perform snat, if the proxy is normal and the direct connection is not working [here refers to the direct in dae's `routing`, not the traffic that OPN does not split to dae and directly goes out of the WAN port. For example, according to the traffic splitting rules configured in the previous section, OPN will split the steam's traffic to pass through dae, dae has configured domain(geosite:steam@cn) -> direct in `routing`, steam cannot log in or download normally], configure nat in the system where dae is installed.

## Performance Optimization

Changing the MTU value between OPN and dae from the default 1500 to 9000 (requires modifying both interfaces and the intermediate link) can achieve lower load.
