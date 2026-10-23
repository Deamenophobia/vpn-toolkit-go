package export

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"

	"github.com/Deamenophobia/vpn-toolkit-go/internal/config"
	"go.yaml.in/yaml/v3"
)

// Target describes what an export actually configures, not a runtime guarantee.
type Target struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Scope       string `json:"scope"`
	Format      string `json:"format"`
	Note        string `json:"note"`
	URI         bool   `json:"uri"`
	RequiredURI bool   `json:"required_uri"`
	CustomCA    bool   `json:"custom_ca"`
}

func Targets() []Target {
	return []Target{
		{ID: "mihomo", Label: "Clash Verge Rev / Mihomo", Scope: "full-profile", Format: "Mihomo YAML", URI: true, CustomCA: true,
			Note: "Import the device's .mihomo.yaml as a local profile. Mihomo 1.19.33 passed native forwarding tests; GUI import and device routing still need testing. Other Mihomo apps need a compatible core."},
		{ID: "shadowrocket", Label: "Shadowrocket", Scope: "connection-only", Format: "AnyTLS URL / optional QR", URI: true, RequiredURI: true,
			Note: "Requires Shadowrocket 2.2.65 or newer; use a current release. Import the URL from the clipboard or scan the QR. Verify TLS server name and certificate checking. Configure routing and DNS in Shadowrocket; iOS import and connection testing are pending."},
		{ID: "v2rayn", Label: "v2rayN (AnyTLS-capable core)", Scope: "connection-only", Format: "AnyTLS URL / optional QR", URI: true, RequiredURI: true,
			Note: "Import the URL from the clipboard into a current v2rayN with an AnyTLS-capable sing-box or Mihomo core. TLS is explicitly enabled in this export. Set routing and DNS in v2rayN; GUI import testing is pending. This is not v2rayNG support."},
		{ID: "stash", Label: "Stash · proxy fragment", Scope: "connection-only", Format: "Stash proxy YAML", CustomCA: false,
			Note: "Advanced: merge the proxy entry into an existing Stash profile, then select it in your routing policy. This is not a complete profile and does not carry DNS, IPv6, UDP policy, or TUN settings. App testing is pending."},
		{ID: "surge", Label: "Surge · proxy fragment", Scope: "connection-only", Format: "Surge [Proxy] fragment", CustomCA: false,
			Note: "Advanced: merge the entry into the [Proxy] section and select it in your routing policy. Requires Surge iOS 5.17.0+ or Mac 6.4.3+; use a current release. App testing is pending. This export does not configure routing or DNS."},
		{ID: "sing-box", Label: "sing-box · outbound fragment", Scope: "connection-only", Format: "sing-box outbound JSON", CustomCA: false,
			Note: "Advanced: merge this outbound into an existing sing-box configuration, then route traffic to its tag. It is not a complete client profile. Requires an AnyTLS-capable version; native schema checked with 1.14.3. GUI app import testing is pending."},
		{ID: "anytls", Label: "Other AnyTLS client · standard URL", Scope: "connection-only", Format: "Standard AnyTLS URL / optional QR", URI: true, RequiredURI: true,
			Note: "Use only if your client explicitly supports the standard AnyTLS URL format. Set routing, DNS, IPv6, and UDP policy in that app. No compatibility claim is made for an unspecified client."},
	}
}

func ClientTarget(id string) (Target, error) {
	if id == "" {
		id = "mihomo"
	}
	for _, t := range Targets() {
		if t.ID == id {
			return t, nil
		}
	}
	return Target{}, errors.New("unknown client target; run vpnctl clients")
}

func (t Target) Validate(c config.Config, uri, qr bool) error {
	if c.TLS.CAFile != "" && (!t.CustomCA || uri || qr || t.RequiredURI) {
		return errors.New("this export cannot preserve custom CA trust; use Mihomo YAML without URL/QR, or configure a publicly trusted server certificate")
	}
	if (uri || qr) && !t.URI {
		return errors.New("URL/QR import is not offered for this client target; use its native fragment or choose a documented URL client")
	}
	return nil
}

func ClientURI(c config.Config, name, password, target string) (string, error) {
	t, err := ClientTarget(target)
	if err != nil {
		return "", err
	}
	if err = t.Validate(c, true, false); err != nil {
		return "", err
	}
	link, err := URI(c, name, password)
	if err != nil {
		return "", err
	}
	if t.ID == "v2rayn" {
		u, err := url.Parse(link)
		if err != nil {
			return "", err
		}
		q := u.Query()
		q.Set("security", "tls")
		q.Set("type", "tcp")
		q.Set("allowInsecure", "0")
		u.RawQuery = q.Encode()
		link = u.String()
	}
	return link, nil
}

func ClientProfile(c config.Config, name, password, target string) (string, []byte, error) {
	t, err := ClientTarget(target)
	if err != nil {
		return "", nil, err
	}
	if err = t.Validate(c, false, false); err != nil {
		return "", nil, err
	}
	if !config.Name(name) {
		return "", nil, errors.New("invalid device name")
	}
	if t.RequiredURI {
		link, err := ClientURI(c, name, password, t.ID)
		return name + ".uri.txt", []byte(link + "\n"), err
	}
	switch t.ID {
	case "mihomo":
		b, err := Mihomo(c, name, password)
		return name + ".mihomo.yaml", b, err
	case "stash":
		p := map[string]any{"name": name, "type": "anytls", "server": c.Server.Address, "port": c.Server.Port, "password": password, "sni": c.TLS.ServerName, "skip-cert-verify": false}
		b, err := yaml.Marshal(map[string]any{"proxies": []any{p}})
		return name + ".stash-proxy.yaml", append([]byte("# Connection fragment only: merge into an existing Stash profile.\n"), b...), err
	case "surge":
		// State passwords use this alphabet. Reject rather than guess INI escaping.
		if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(password) {
			return "", nil, errors.New("Surge export requires a generated URL-safe device password")
		}
		if !config.Host(c.Server.Address) || !config.Host(c.TLS.ServerName) {
			return "", nil, errors.New("invalid server identity")
		}
		b := fmt.Sprintf("# Connection fragment only: merge this entry into your [Proxy] section.\n[Proxy]\n%s = anytls, %s, %d, password=%s, sni=%s, skip-cert-verify=false\n", name, c.Server.Address, c.Server.Port, password, c.TLS.ServerName)
		return name + ".surge-proxy.conf", []byte(b), nil
	case "sing-box":
		p := map[string]any{"type": "anytls", "tag": name, "server": c.Server.Address, "server_port": c.Server.Port, "password": password, "tls": map[string]any{"enabled": true, "server_name": c.TLS.ServerName, "insecure": false}}
		b, err := json.MarshalIndent(map[string]any{"outbounds": []any{p}}, "", "  ")
		return name + ".sing-box-outbound.json", append(b, '\n'), err
	}
	return "", nil, errors.New("client exporter is unavailable")
}

func (t Target) Instructions() []byte {
	text := fmt.Sprintf("Client: %s\nFormat: %s\nScope: %s\n\n%s\n\n", t.Label, t.Format, t.Scope, t.Note)
	if t.Scope == "connection-only" {
		text += "This export carries only endpoint, credential, and TLS identity. It does NOT apply client.mode, local listener ports, DNS/bootstrap DNS, IPv6 policy, direct routes, or the UDP switch. Set and verify those in the destination app. Do not import this as a complete routing profile.\n\n"
	}
	text += "AnyTLS URLs and QR images always contain connection settings only, even when exported alongside a complete Mihomo profile. They do not carry DNS or routing policies. App or global overrides may change TLS and routing behavior; review the imported settings.\n\nKeep certificate verification enabled. Share only a device's own file or QR. server.json contains ALL active device credentials and belongs on your server. Local generation does not deploy the server. After rotation/revocation, deploy the new server.json and restart the server to enforce it.\n"
	return []byte(text)
}
