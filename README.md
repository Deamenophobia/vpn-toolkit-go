# VPN toolkit

Generate AnyTLS server configurations and client profiles with a Go CLI or local web UI.

## Build

Requires Go 1.26.10 or newer.

```sh
go build -trimpath -o bin/vpnctl ./cmd/vpnctl
```

On Windows, build to `bin/vpnctl.exe` and use `.\bin\vpnctl.exe` in the commands below.

## Use

Replace the example address with your server:

```sh
./bin/vpnctl init --server vpn.example.com
```

Set the server certificate and key paths in `vpn.yaml`, then generate a device profile:

```sh
./bin/vpnctl client add --name laptop
./bin/vpnctl render --out bundle-1
```

Follow the [server installation guide](docs/INSTALL.md), then import `bundle-1/laptop.mihomo.yaml` into your client. Keep generated files private.

## Local web UI

```sh
./bin/vpnctl ui --config vpn.yaml
```

Open the private link printed in the terminal. Stop with Ctrl+C.

[Usage guide](docs/USAGE.md) · [Client exports and QR codes](docs/CLIENTS.md) · [Configuration](docs/CONFIGURATION.md) · [MIT license](LICENSE)
