# Local CA and Client Certificates

The daemon manages dae's local CA. API HTTPS and transparent MITM share the same certificate identity. The API does not depend on MITM: setting only `api.listen` makes both HTTP and HTTPS pages and the complete API available on the same port.

## Automatic initialization and persistence

No certificate paths are required by default. During configuration preparation, the daemon generates a self-signed root CA if no certificate is configured and the managed directory does not exist. This is independent of TCP API listening and `mitm.enabled`, so the Unix API can also export the public certificate:

| Item | Default |
| --- | --- |
| Managed directory | `/var/lib/dae/pki`, permissions `0700` |
| Public certificate | `ca.pem`, permissions `0644` |
| Private key | `ca.key`, permissions `0600` |
| Name and validity | `dae Local CA`, 3650 days |

`DAE_LOCATION_CACHE` changes the base directory; the managed directory is always its `pki` subdirectory. Startup, reloads and changes to the MITM switch reuse the same CA. Disabling TCP API listening or MITM neither deletes nor regenerates it. Generation atomically publishes the complete directory, preserving a single identity even with concurrent initialization.

If a certificate in an existing managed directory is missing, corrupted or expired, or the private key has incorrect permissions or does not match, startup or reload fails instead of automatically replacing the CA. A failed reload preserves the running configuration. Restore the original files or explicitly configure a new CA. Back up the entire `pki` directory, including the private key; do not delete it as temporary cache data. The log records the accepted CA's SHA-256 fingerprint.

Automatic generation only supplies the server's certificate source; clients must still install and trust the public CA. The private key always stays on the dae host.

The API HTTPS management leaf certificate and private key are stored separately under `/var/lib/dae/api-tls`, keyed by CA fingerprint and router IP; this directory is also controlled by `DAE_LOCATION_CACHE`. Each identity is atomically saved in a PEM file with permissions `0600`. Access, restarts and reloads reuse the same certificate and key while they remain valid. Management leaf certificates are valid for 90 days, capped by the CA's expiry; issuance and persistence occur only when the file is missing or the certificate has expired. Existing files with corruption, mismatched keys or unsafe permissions are rejected rather than silently replaced.

Certificate trust tests issue a separate temporary leaf certificate and a new key, held only in memory. The challenge lasts one minute; the temporary certificate allows five additional minutes for client clock skew, capped by the CA's expiry, without extending the challenge deadline. During a test, only new TLS connections from the initiating source IP to that router IP use the challenge certificate. A successful proof consumes the challenge; unfinished challenges expire. Once no challenges remain for that address pair, new connections use the original management certificate again. Clients sharing a source IP share this temporary selection. Tests do not rewrite management certificate files, and a restart discards all temporary challenges. Short-lived MITM leaf certificates still use a separate in-memory cache.

## Explicit CA configuration and commands

To use an existing CA, configure it at the top level:

```text
certificate {
  ca_cert: '/srv/dae/home.pem'
  ca_key: '/srv/dae/home.key'
}
```

Both paths must be set or both left empty. Relative paths are resolved against `DAE_LOCATION_CACHE`. Explicit paths only load and validate the certificate and private key; missing files are not generated, and there is no fallback to the managed CA.

```sh
sudo dae ca info
sudo dae ca export --format pem
sudo dae ca export --format der --output /tmp/dae-ca.cer
sudo dae ca export --format mobileconfig --output /tmp/dae-ca.mobileconfig
```

`info` reads only the public certificate and displays its validity, serial number and SHA-256 fingerprint. `export` exports only the public certificate, writing PEM to standard output by default and refusing to overwrite output files. Commands use the managed directory by default. The service and terminal should use the same `DAE_LOCATION_CACHE`; see [Cache directory (Chinese)](../../zh/configuration/cache-directory.md). Both `info` and `export` accept `--cert` to select another public certificate.

You can also generate the managed CA before the first startup with `sudo dae ca generate`, or specify both paths to generate a separate CA:

```sh
sudo dae ca generate --cert /srv/dae/home.pem \
  --key /srv/dae/home.key --name 'Home dae CA' --valid-days 3650
```

Generation refuses to overwrite existing files or a managed directory. Explicit CLI paths are relative to the current working directory. To replace the CA, generate it at new paths, install and trust it on clients, then update the `certificate` section and reload. After the new identity is published, old TLS connections cannot access the new CA's metadata; ordinary reloads using the same CA preserve HTTPS connections. Once successful, remove the old certificate from clients and archive or delete the old private key.

## Providing downloads for iPhone / iPad

Configure `global { lan_interface: br-lan }` and `api { listen: 9080 allow_lan_anonymous: true }`, then reload; replace the interface name with the actual LAN interface. Open `http://192.168.1.1:9080/` in Safari, substituting the router's actual LAN IP. The native API requires a direct connection by IP, and a bare port requires a LAN interface pattern. A pattern with no currently matching interfaces does not fall back to all addresses. MITM need not be enabled: the page's **Certificate & browser verification** section provides downloads and HTTPS verification. The HTTP page is only an anonymous installation guide and does not accept API keys. If anonymous access is disabled, first export the public CA through the local Unix API and distribute it through a trusted channel.

1. Compare the page's fingerprint with the SHA-256 fingerprint in dae's startup log or `dae ca info`.
2. In the **Download** menu, choose **Configuration profile** to download `ca.mobileconfig`.
3. Install the profile in **Settings → General → VPN & Device Management**.
4. Enable full trust for this CA in **Settings → General → About → Certificate Trust Settings**.
5. Return to the page and click **Test certificate**. Confirm that **CA trust** shows **CA trusted by this browser**; you can then use `https://192.168.1.1:9080/`.
6. For transparent MITM, enable MITM in the daemon, then set **HTTPS Modules** to **On** for the current device. The page automatically tests again and displays the **HTTPS interception** result.

Manual installation does not automatically grant TLS trust; step 4 is required. See [Apple's official instructions](https://support.apple.com/en-us/102390). Before removing the profile, turn off MITM for the device.

Through an HTTPS reverse proxy, key/Cookie access can still download the CA, but self-device features and browser CA/MITM verification are unavailable. Verification requires a direct connection to the native API by IP. The browser trusting the proxy page's certificate, the proxy verifying dae's CA, and the browser trusting dae's CA are three different facts; the proxy's upstream TLS handshake cannot replace browser verification. Development mode does not additionally hide verification controls; availability depends on actual direct connectivity and authorization.

HTTPS login sessions use the `__Host-dae-session` HttpOnly Cookie; the HTTP setup page does not use it to log in. Cookies for the same hostname/IP are not isolated by port. A dedicated hostname is recommended for an independent management page, deployed according to the [same-origin HTTPS reverse proxy example](api-client.md#same-origin-https-reverse-proxy).

Tests temporarily serve a newly issued challenge certificate for connections from the initiating source IP to that router IP and require a new TLS handshake. A previously accepted certificate warning does not count as CA trust. You do not need to visit HTTPS first: test directly from the HTTP installation page. The persistent management certificate, CA and MITM certificates remain unchanged. The temporary certificate is removed when its challenge is proved or expires, and the management certificate is restored once no challenges remain for that address pair. New HTTPS connections relying only on an exception for the management certificate may be rejected while a challenge is valid; use the HTTP installation page in that case. Tests verify only the current browser, not the system or other applications' trust stores, and work without a MAC or enabled MITM. Transparent MITM uses an additional short-lived challenge at a virtual IP:443 to confirm actual capture and decryption; see [Certificate and MITM tests](api.md#certificate-and-mitm-tests).
