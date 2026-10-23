# Initial engine and client

Use sing-box 1.14.3 for the first AnyTLS server adapter and Mihomo 1.19.33 for the first client exporter. These are external programs; the Go CLI does not carry packets.

The application uses system/public CA verification by default. An optional local CA file exports a CA fingerprint for Mihomo. Leaf pins are rejected because their name/chain verification behavior differs. The generic AnyTLS URI has no standard CA field, so URI and QR exports reject custom-CA configurations rather than discarding their trust setting.

Engine versions are pinned for the first implementation. Review upstream migrations when changing the pair. The protocol choice is isolated behind the engine adapter; supporting another protocol requires matching server and client exporters.

Official references:

- [sing-box AnyTLS configuration](https://sing-box.sagernet.org/configuration/inbound/anytls/)
- [sing-box TLS configuration](https://sing-box.sagernet.org/configuration/shared/tls/)
- [Mihomo AnyTLS configuration](https://wiki.metacubex.one/en/config/proxies/anytls/)
- [Mihomo certificate fingerprint semantics](https://wiki.metacubex.one/en/config/proxies/tls/)
- [AnyTLS URI specification](https://github.com/anytls/anytls-go/blob/main/docs/uri_scheme.md)

