# Security boundaries

The CLI prepares configuration and credentials. sing-box and Mihomo perform the transport encryption. Encryption covers the client-to-server hop; use HTTPS or other application encryption beyond that hop. The exit address is visible to destination services.

Certificate verification is required. Public CA trust is the default. The optional CA fingerprint mode uses name and chain verification in the pinned Mihomo version. Review trust settings before distributing profiles.

Configuration and state are local administrator inputs. Use a dedicated private directory on a local filesystem. The toolkit does not defend against another process already running as the same OS user or a machine administrator.

Treat state, bundles, profiles, connection links, and QR images as secrets. Keep them out of Git, screenshots, issue reports, and public logs. The state directory and export directories use restrictive platform permissions. Export only a device's own profile to it.

The optional web UI binds only 127.0.0.1 and requires a fresh random bearer token for every API operation. Keep the launch link private; it grants access to device operations and generated credentials. The token is carried in the URL fragment, removed on page load, and retained only in browser memory. Reopen the launch link after a browser reload. Host and origin checks reject foreign websites; no CORS access is enabled. Local HTTP is used only on loopback. Do not expose or forward the UI port, or place it behind a reverse proxy.

The UI applies no server changes and cannot prove runtime state. Browser downloads inherit the browser's destination and permissions, not the toolkit's protected-file permissions. Prefer the private export directory for sensitive files and protect any copies. The UI does not protect against browser extensions, another process running as the current user, or administrators.

Revocation requires applying the new server configuration and restarting the engine. Old snapshots can restore old credentials. The manifest deliberately records not_applied rather than claiming that a live service matches local state.

TUN settings do not by themselves establish a kill switch or prove that DNS and IPv6 cannot bypass the tunnel. Routing and disconnect behavior depend on the client and operating system.

Keep vulnerability reports free of credentials and use the repository owner's private reporting channel once one is established.
