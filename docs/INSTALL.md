# Install one Linux server

Use a maintained Ubuntu LTS server with systemd and an existing administrator connection. Adapt account names and paths to your installation.

## Prepare

1. Install the pinned sing-box version from the official release or package source and verify the download checksum. The service template assumes /usr/local/bin/sing-box; edit it if your package uses a different path.
2. Obtain a trusted certificate and key for the configured TLS identity using an established certificate tool, or use the documented private CA mode. Keep certificate renewal working independently of the CLI.
3. Generate a private bundle on your workstation. Check that READY exists and inspect its manifest.
4. Transfer server.json and vpn-toolkit.service securely to the server. Transfer client files only to their intended devices.
5. Allow the configured TCP port through the host and cloud firewalls. UDP application traffic is carried inside AnyTLS's transport; this configuration does not require opening the same UDP port. Keep administrator access intact.

Create a dedicated unprivileged system user and directories, adapting account creation for your distribution:

~~~sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin vpn-toolkit
sudo install -d -o root -g vpn-toolkit -m 0750 /etc/vpn-toolkit
sudo install -d -o root -g vpn-toolkit -m 0750 /etc/vpn-toolkit/tls
~~~

Skip account creation if the account already exists. Install certificate/key files so the service user can read them: root owns the files, group vpn-toolkit has read access, and other users have none. Ensure certificate renewal preserves that access. Follow the actual certificate tool's renewal hook instructions.

## Stage and start

Run from the directory holding the transferred server.json and service file:

~~~sh
sudo install -o root -g vpn-toolkit -m 0640 server.json /etc/vpn-toolkit/server.next.json
sudo -u vpn-toolkit /usr/local/bin/sing-box check -c /etc/vpn-toolkit/server.next.json
~~~

Only after validation passes:

~~~sh
sudo mv /etc/vpn-toolkit/server.next.json /etc/vpn-toolkit/server.json
sudo install -o root -g root -m 0644 vpn-toolkit.service /etc/systemd/system/vpn-toolkit.service
sudo systemctl daemon-reload
sudo systemctl enable --now vpn-toolkit.service
sudo systemctl status vpn-toolkit.service
~~~

The template uses the configured public listener, an unprivileged user, and only the capability needed for a low port. It exposes no management API. Edit its paths and account names if you choose different installation defaults.

Unlike a WireGuard gateway, this proxy service opens outbound connections itself. It does not need IP forwarding or a blanket NAT/firewall rewrite.

## Apply a credential or configuration update

Serialize server updates; do not deploy from two terminals at once.

1. Render a new bundle after the local change. Keep the currently working server configuration until validation and an authenticated connection succeed.
2. Install the candidate as server.next.json and validate it as the service user.
3. Copy the current server.json to a root-owned, group-readable server.previous.json.
4. Move the validated candidate over server.json, then restart the service. A restart disconnects existing sessions and enforces changed credentials.
5. Verify the service and an authenticated client connection. Confirm the replaced/revoked credential fails.

If a normal configuration update fails, restore server.previous.json and restart. If the update was a security revocation, restoring the old file would restore the revoked credential: keep the service stopped until the corrected revocation configuration validates.

A server with no active devices renders an empty user list and rejects authentication. It does not become an unauthenticated proxy.

For certificate renewal, install the new chain/key with the required permissions, validate the service configuration, and restart the service. The first release does not automate issuance or renewal.

## Connect the client

Import the device's complete Mihomo YAML into a compatible client. Select the profile, enable the required client/service permissions for TUN, and review application-level overrides. For other export formats, follow the [client instructions](CLIENTS.md).

Configure routing, DNS, and IPv6 in the client for your intended use. Proxy mode affects only applications using the proxy; whole-device routing requires the client's TUN mode.

