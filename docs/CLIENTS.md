# Client exports and imports

Choose an AnyTLS-capable client and the matching export format. Client behavior depends on its core version, import format, and application settings. The toolkit generates server configuration for sing-box.

Choose a target with `vpnctl render --client TARGET`, or use the **VPN client** selector in the local UI. `vpnctl clients` lists the choices without requiring a configuration file. Changing export targets keeps the server and device credentials unchanged.

| Target | Application | Output | Import requirements |
| --- | --- | --- | --- |
| mihomo (default) | Clash Verge Rev and other compatible Mihomo-based apps | Complete device `.mihomo.yaml`; optional standard URL/QR | Import the YAML profile and select it. See [engine versions](COMPATIBILITY.md). |
| shadowrocket | Shadowrocket 2.2.65+; use a current release | Device `.uri.txt`; optional `.qr.png` | Import the AnyTLS URL or scan the QR; configure routing and DNS in the app. |
| v2rayn | Current v2rayN with an AnyTLS-capable core | Device `.uri.txt`; optional `.qr.png` | Import the URL and select a compatible core. The export includes explicit TLS settings. |
| stash | Current Stash with AnyTLS support | `.stash-proxy.yaml` connection fragment | Merge into an existing profile and select the node in its policy. |
| surge | Surge iOS 5.17.0+ / Mac 6.4.3+; use a current release | `.surge-proxy.conf` connection fragment | Merge the entry into `[Proxy]` and configure its policy. |
| sing-box | AnyTLS-capable sing-box | `.sing-box-outbound.json` connection fragment | Merge the outbound into an existing client configuration and select it in routing. |
| anytls | Another app that explicitly accepts standard AnyTLS URLs | `.uri.txt`; optional `.qr.png` | Standard-format export only; no compatibility claim for an unspecified app. |

Each bundle also contains server files, a manifest stating the selected client and scope, and **IMPORT.txt** with the matching instructions. A fragment contains endpoint, credential, and TLS settings; it is not a complete working client configuration by itself. Do not share the server file with a client: it contains all active device passwords.

## Shadowrocket

~~~sh
vpnctl client add --name iphone
vpnctl render --out iphone-bundle --name iphone --client shadowrocket --qr
~~~

1. Use a server certificate trusted by the destination device, matching the configured TLS server name.
2. Open the device's QR image and scan it with Shadowrocket, or copy the contents of `iphone.uri.txt` into its node-import workflow. The local web UI's **Show QR** button displays the code without exposing its HTTP listener to the phone.
3. Review the imported AnyTLS address, port, password, and TLS server name. Leave certificate verification enabled. The URL is a node connection link, not a hosted subscription address.
4. Set Shadowrocket's routing/global mode, DNS, IPv6, and UDP behavior for your intended use. Its own settings and overrides control these; the QR does not configure them.
5. Deploy the matching `server.json` using the [installation guide](INSTALL.md), then select the node and connect.

The URL file is always included for this target. QR output remains opt-in. Neither the URL nor the QR is printed in ordinary CLI output. Treat both as credentials.

## Other workflows

~~~sh
vpnctl render --out desktop-bundle --name laptop --client mihomo
vpnctl render --out v2rayn-bundle --name laptop --client v2rayn --qr
vpnctl render --out stash-bundle --name ipad --client stash
vpnctl render --out surge-bundle --name mac --client surge
vpnctl render --out sing-box-bundle --name android --client sing-box
~~~

Create those device names first. For v2rayN, import the URL from the clipboard and use an AnyTLS-capable sing-box or Mihomo core. Review certificate verification after import; app-wide preferences can override imported settings. v2rayN support does not establish v2rayNG support.

Stash, Surge, and sing-box exports are connection fragments. Merge them into an existing profile, add/select the corresponding policy or outbound, and configure routing and DNS in that application. These exporters omit Mihomo-specific TUN, DNS, and certificate-pin fields. URI/QR flags are unavailable for these fragment targets.

AnyTLS URLs and fragments do not apply `client.mode`, local listener ports, DNS/bootstrap DNS, direct CIDRs, IPv6 policy, or the UDP switch. The complete Mihomo YAML does apply those settings. A native parser accepting a fragment does not prove forwarding or routing behavior in a GUI app.

Custom-CA export is currently supported only by Mihomo YAML. Other targets reject it instead of losing the trust setting or enabling insecure TLS. A publicly trusted certificate is the simplest interoperable path for the listed mobile apps.

Use the generic `anytls` target only when the destination app explicitly accepts standard AnyTLS URLs. WireGuard-only and OpenVPN-only clients require a different server protocol and cannot use these exports.

## Upstream references

- [AnyTLS standard URI format](https://github.com/anytls/anytls-go/blob/main/docs/uri_scheme.md) and [upstream client compatibility notes](https://github.com/anytls/anytls-go/blob/main/readme.md).
- [Shadowrocket's App Store listing and release history](https://apps.apple.com/us/app/shadowrocket/id932747118).
- [v2rayN subscription formats](https://github.com/2dust/v2rayN/wiki/Description-of-subscription), [AnyTLS parser](https://github.com/2dust/v2rayN/blob/master/v2rayN/ServiceLib/Handler/Fmt/AnytlsFmt.cs), and [shared URI query parser](https://github.com/2dust/v2rayN/blob/master/v2rayN/ServiceLib/Handler/Fmt/BaseFmt.cs).
- [Stash protocol and TLS fields](https://stash.wiki/en/proxy-protocols/proxy-types).
- [Surge AnyTLS](https://manual.nssurge.com/policies/anytls.html) and [TLS parameters](https://manual.nssurge.com/policies/tls.html).
- [sing-box AnyTLS outbound](https://sing-box.sagernet.org/configuration/outbound/anytls/) and [TLS fields](https://sing-box.sagernet.org/configuration/shared/tls/).
