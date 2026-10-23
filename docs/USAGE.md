# Usage guide

The toolkit generates configurations and device credentials. Install sing-box separately on the server and use an AnyTLS-capable client. See [engine versions](COMPATIBILITY.md) and [server installation](INSTALL.md).

Commands below use `vpnctl` on PATH. From a source checkout, use `./bin/vpnctl` or `.\bin\vpnctl.exe` on Windows. Use a private working directory; `--config PATH` selects a configuration other than `vpn.yaml`.

## Local web UI

```sh
vpnctl ui --config vpn.yaml
```

Open the private launch link printed in the terminal. A missing configuration starts the setup form; its parent directory must exist. Edit the server settings, save, add a device, and choose an export target. The interface is embedded in the executable and requires no frontend installation.

The UI listens on `127.0.0.1` with a random port. Use `--ui-port 8787` to select a fixed port. Keep the launch link private and reopen it after a browser reload. Stop the UI with Ctrl+C.

Exports are saved under the configured private state directory in `exports/`. Download buttons serve files from the current UI session. Browser downloads use the browser's destination and permissions; protect those copies. Use **Show QR** to display an optional generated QR image for a phone to scan.

Saving settings or changing a device updates local configuration. Apply the generated server configuration separately using the installation guide.

## Configure and export

```sh
vpnctl init --server vpn.example.com
```

Replace the example endpoint and edit `vpn.yaml` to set the server certificate and key paths. Other settings are described in the [configuration reference](CONFIGURATION.md).

```sh
vpnctl client add --name laptop
vpnctl render --out bundle-1
```

The default bundle contains:

| File | Purpose |
| --- | --- |
| `server.json` | sing-box server configuration with all active device credentials |
| `laptop.mihomo.yaml` | Complete Mihomo profile for this device |
| `vpn-toolkit.service` | Editable systemd service template |
| `manifest.json` | Desired configuration revision, export target, and `not_applied` status |
| `READY` | Export completion marker |
| `IMPORT.txt` | Instructions for the selected client |

Every export requires a new output directory. Follow [installation](INSTALL.md) to deploy the server files, then transfer only the device's own client files to it. State, profiles, connection links, and QR images contain credentials. Keep them outside source control. The certificate private key is not copied into the bundle.

## Select a client

```sh
vpnctl clients
vpnctl client add --name iphone
vpnctl render --out iphone-bundle --name iphone --client shadowrocket --qr
```

Scan the generated QR or import `iphone.uri.txt` in an AnyTLS-capable Shadowrocket. Configure routing and DNS in the app. [Client instructions](CLIENTS.md) describe each target's format and import steps.

For a standard connection link and QR alongside a Mihomo profile:

```sh
vpnctl render --out laptop-bundle --name laptop --uri --qr
```

Custom-CA configurations require Mihomo YAML because standard AnyTLS URLs cannot carry that trust setting. Keep certificate verification enabled.

## Manage devices

```sh
vpnctl client list
vpnctl client rotate --name laptop
vpnctl render --out bundle-2
vpnctl client revoke --name laptop
vpnctl render --out bundle-3
```

After each change, deploy the matching server configuration and restart sing-box to enforce it and end existing sessions. After rotation, also replace the device's profile. Revoked device names cannot be reused. Old bundles retain old credentials; protect or remove them when no longer needed.

## Inspect and validate configuration

```sh
vpnctl config
vpnctl check --kind server --file bundle-1/server.json --binary /usr/local/bin/sing-box
vpnctl check --kind client --file bundle-1/laptop.mihomo.yaml --binary /path/to/mihomo
```

Server validation requires access to the certificate/key paths on that machine. Use the versions listed in [engine compatibility](COMPATIBILITY.md). These commands validate configuration; they do not deploy it or establish a connection.
