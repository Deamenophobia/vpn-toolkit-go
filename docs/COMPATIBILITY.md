# Engine versions

Install the engines separately. The toolkit's native configuration checks require these versions:

| Role | Engine | Version |
| --- | --- | --- |
| Server | sing-box | 1.14.3 |
| Complete client profile | Mihomo | 1.19.33 |
| sing-box outbound fragment | sing-box | 1.14.3 |

Obtain the appropriate platform archive from the official [sing-box](https://github.com/SagerNet/sing-box/releases) or [Mihomo](https://github.com/MetaCubeX/mihomo/releases) release page and verify its published checksum before installation.

## Native configuration checks

```sh
vpnctl check --kind server --file bundle-1/server.json --binary /usr/local/bin/sing-box
vpnctl check --kind client --file bundle-1/laptop.mihomo.yaml --binary /path/to/mihomo
vpnctl check --kind sing-box-client --file android-bundle/android.sing-box-outbound.json --binary /path/to/sing-box
```

Server checks require access to the referenced certificate and key. A successful configuration check does not establish a live connection. Install server updates using the [staging and restart workflow](INSTALL.md).

For application-specific formats and import instructions, see [client exports](CLIENTS.md). Review upstream migration notes and update the adapter, exporters, and version requirements together when changing engine versions.
