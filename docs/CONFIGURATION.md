# Configuration

Use --config PATH after any command to select the configuration file. Otherwise vpn.yaml is used. Explicit --server, --port, --tls-name, and --mode flags override file values for that operation; they do not rewrite the file. File values override defaults. Lists replace defaults. Unknown fields and multiple YAML documents are rejected.

The optional `ui` command accepts only `--config` and `--ui-port`. Its form edits and saves the selected YAML file directly. Save pending form edits before using device or export controls. The state directory is read-only in the browser; stop the UI before changing it in the YAML file. Malformed YAML or unknown fields must be corrected in a text editor. The web UI does not modify the installed Clash client's active configuration.

| Field | Default | Meaning |
| --- | --- | --- |
| version | 1 | Configuration schema |
| engine | sing-box-anytls | The implemented engine adapter |
| state_dir | private | Dedicated private state directory, relative to the configuration file |
| server.address | Required | Advertised hostname or IP; never inferred from a cloud account |
| server.port | 443 | AnyTLS TCP listen and advertised port |
| server.listen | 0.0.0.0 | Bind address on the server |
| server.dns | 1.1.1.1 | Server-side UDP DNS resolver for destination names |
| server.log_level | warn | warn, error, or info |
| tls.server_name | Required | Identity checked against the server certificate; init defaults it to the endpoint |
| tls.certificate | /etc/vpn-toolkit/tls/fullchain.pem | Certificate chain path on the server |
| tls.key | /etc/vpn-toolkit/tls/privkey.pem | Private key path on the server |
| tls.ca_file | Unset | Optional local CA PEM used to export a Mihomo CA fingerprint |
| client.mode | tun | tun for device routing intent, proxy for explicitly configured applications |
| client.mixed_port | 7890 | Loopback-only HTTP/SOCKS listener |
| client.dns_listen_port | 1053 | Loopback DNS listener |
| client.ipv6 | block | block or tunnel; requires the actual client routing checks |
| client.dns | HTTPS resolver at 1.1.1.1 | DNS resolver URLs forced through the VPN node |
| client.bootstrap_dns | HTTPS resolver at 1.1.1.1 | Direct resolvers used to locate the VPN endpoint |
| client.direct_cidrs | Empty | Explicit destination networks allowed to bypass the VPN |
| client.udp | true | Enable UDP forwarding in the client profile |

TLS key and certificate paths belong to the target server and are preserved as written. Local state and CA paths resolve against the configuration file. Defaults are implemented centrally in internal/config; edit the YAML for deployment-specific values.

Client resolvers currently accept HTTPS URLs. Bootstrap URLs must use an IP hostname to avoid a DNS bootstrap cycle. The bootstrap query for the VPN hostname is a deliberate direct connection. Application DoH connections are forced through the VPN. DNS from the server to its configured resolver is outside the client-to-server encrypted hop.

The first adapter exposes these typed settings rather than arbitrary native JSON merging. Unsupported fields fail clearly. To use other native engine features, manage an edited native configuration separately; rendering again produces a fresh managed configuration.

## Device state

The state directory contains state.json and a writer lock. State contains one random 256-bit password per active device and a monotonically increasing desired-state revision. File updates use a cross-process lock and a same-directory replacement. Failed writes do not intentionally truncate the existing state.

The directory is dedicated to the toolkit. On Unix it uses 0700 directories and 0600 files; on Windows it restricts its DACL to the current user and SYSTEM. Do not select a shared directory, a filesystem root, or a network filesystem for state. Keep backups private and stop management commands before restoring one.

Revocation removes the password from desired state. Existing exported files may still contain it, and a running server retains the old configuration until restarted with the new one. The toolkit does not claim a synchronized runtime state.

## Trust and exports

Without tls.ca_file, the client verifies the server using its normal trust store and configured server name. An optional CA file must contain one currently valid CA certificate. The exporter hashes that CA into Mihomo's fingerprint field. The server must present the chain required for the client to verify it.

The toolkit rejects leaf certificate files in this field because leaf fingerprint verification has different name and chain semantics. Generic AnyTLS URIs cannot express this CA setting and are rejected for that mode.

URI/QR export requires --uri or --qr. Both are generated locally. They are not hosted subscription URLs, and no upload service is contacted.

## Routing

The full profile routes unmatched traffic through the single node. Optional direct CIDRs are explicit exceptions. IPv6 block mode rejects IPv6 destinations inside the proxy and disables AAAA answers from its DNS; the TUN template includes an IPv6 interface address to support route capture. Verify actual IPv6 capture on the target OS before relying on it.

Proxy mode affects only applications using the proxy. TUN mode needs client privileges and can be affected by Clash Verge settings or profile overrides. The toolkit never changes the installed client's running configuration automatically.

