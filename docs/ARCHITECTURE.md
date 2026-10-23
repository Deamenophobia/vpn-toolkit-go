# Architecture

The CLI is a short-lived management program. sing-box runs independently as the server process, and Mihomo runs in the existing client. No Go management daemon is required.

| Package | Responsibility |
| --- | --- |
| cmd/vpnctl | Command parsing and readable, secret-free output |
| internal/config | Defaults, typed YAML, validation and override inputs |
| internal/state | Serialized desired-state changes and credential generation |
| internal/privatefs | Restricted permissions and file replacement |
| internal/app | Device operations and a consistent export snapshot |
| internal/engine | Native server configuration behind an adapter interface |
| internal/export | Client capability catalogue, Mihomo profiles, client-specific connection fragments, and AnyTLS URIs |
| internal/host | Opt-in native checks and an editable systemd template |
| internal/webui | Optional loopback HTTP interface and embedded browser assets; calls the same application operations |
| integration | Real engine tests on disposable loopback ports |

The configuration contains references to local state and server key paths, never inline passwords. Rendering reads one locked state revision and creates a new private directory. It precomputes outputs before writing them, writes a manifest, and marks completion last. A failed export must not be deployed.

The engine adapter only owns native server rendering at present. Add another method when an actual second implementation needs it. Client format and protocol capabilities remain explicit; the application must reject exports that cannot preserve authentication or trust information.

Client targets are a small catalogue in `internal/export`, exposed by both `vpnctl clients` and the local UI. They describe format, full-profile versus connection-only scope, optional URL support, and custom-CA capability. Application rendering selects one target per bundle while retaining the same server credentials. Each bundle includes matching import instructions and target/scope metadata. Adding a client formatter does not add a new server protocol or a general plugin SDK.

The first release provides manual server installation and replacement rather than remote SSH automation. Desired-state revision is not an applied-state claim. Any later installer must validate a candidate, preserve the last usable configuration, and handle failed restarts before it reports success.

Cryptographic primitives and TLS negotiation belong to established libraries and engines. The CLI uses the operating system random source for credentials and never implements a transport protocol.

## Optional local interface

`vpnctl ui` runs only while explicitly started. Go's standard HTTP server serves embedded HTML, CSS, and JavaScript without frontend dependencies. The UI prepares configuration; it has no traffic engine, remote shell, background startup service, or connection-status inference.

The listener binds IPv4 loopback only. Exact Host checks, a random session bearer token, and same-origin checks protect the API. The page keeps the token in memory and removes it from the URL. Responses prohibit caching and framing. Device lists contain names and desired-state status, never credentials. Credential-bearing file downloads require authorization and an allowlist of generated files.

Config saves check a content revision before replacing the selected file, rejecting stale browser edits. State changes retain the shared cross-process store lock. Stop the UI before moving state or making external configuration edits; the UI does not provide cross-process transactions for configuration files. Exports remain immutable snapshots, and changing desired state marks the displayed export as stale. Deployment remains a separate operator step.

