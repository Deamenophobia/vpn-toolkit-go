package export

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/Deamenophobia/vpn-toolkit-go/internal/config"
	"go.yaml.in/yaml/v3"
)

func clientConfig() config.Config {
	c := config.Defaults()
	c.Server.Address = "2001:db8::7"
	c.TLS.ServerName = "vpn.example.com"
	return c
}

func TestClientURIsPreserveCredentialsAndTrust(t *testing.T) {
	c := clientConfig()
	for _, target := range []string{"mihomo", "shadowrocket", "v2rayn", "anytls"} {
		for _, password := range []string{"generated_URL-safe-123", "a:b@c/?#%+", "测试 密码"} {
			link, err := ClientURI(c, "device name", password, target)
			if err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(link)
			if err != nil {
				t.Fatal(err)
			}
			if u.Scheme != "anytls" || u.User.Username() != password || u.Hostname() != c.Server.Address || u.Port() != "443" || u.Fragment != "device name" {
				t.Fatal("URI round trip changed connection settings")
			}
			if _, has := u.User.Password(); has {
				t.Fatal("auth must be URI username only")
			}
			q := u.Query()
			if q.Get("sni") != c.TLS.ServerName || q.Get("insecure") != "0" {
				t.Fatal("TLS identity/verification lost")
			}
			if target == "v2rayn" && (q.Get("security") != "tls" || q.Get("type") != "tcp" || q.Get("allowInsecure") != "0") {
				t.Fatal("v2rayN TLS fields missing")
			}
		}
	}
}
func TestNativeFragmentsAreConnectionOnly(t *testing.T) {
	c := clientConfig()
	password := "generated_URL-safe-123"
	_, b, err := ClientProfile(c, "phone", password, "stash")
	if err != nil {
		t.Fatal(err)
	}
	var st struct{ Proxies []map[string]any }
	if err = yaml.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	p := st.Proxies[0]
	if p["skip-cert-verify"] != false || p["sni"] != c.TLS.ServerName || p["password"] != password {
		t.Fatal("Stash trust/credential changed")
	}
	if _, ok := p["fingerprint"]; ok {
		t.Fatal("Mihomo-specific CA fingerprint leaked into Stash")
	}
	_, b, err = ClientProfile(c, "phone", password, "sing-box")
	if err != nil {
		t.Fatal(err)
	}
	var sb struct {
		Outbounds []struct {
			Type, Tag, Server, Password string
			TLS                         struct {
				Enabled    bool
				ServerName string `json:"server_name"`
				Insecure   bool
			}
		}
	}
	if err = json.Unmarshal(b, &sb); err != nil {
		t.Fatal(err)
	}
	o := sb.Outbounds[0]
	if o.Type != "anytls" || o.Tag != "phone" || o.Server != c.Server.Address || o.Password != password || !o.TLS.Enabled || o.TLS.Insecure || o.TLS.ServerName != c.TLS.ServerName {
		t.Fatal("sing-box outbound changed security settings")
	}
	_, b, err = ClientProfile(c, "phone", password, "surge")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "skip-cert-verify=false") || !strings.Contains(string(b), "sni="+c.TLS.ServerName) {
		t.Fatal("Surge TLS options lost")
	}
	for _, target := range Targets() {
		if target.ID != "mihomo" && (!strings.Contains(string(target.Instructions()), "does NOT apply") || target.Scope != "connection-only") {
			t.Fatal("node export masquerades as routing profile")
		}
	}
}
func TestClientTargetsRejectUnsafeCombinations(t *testing.T) {
	c := clientConfig()
	c.TLS.CAFile = "custom-ca.pem"
	for _, target := range Targets() {
		if target.ID != "mihomo" {
			if _, _, err := ClientProfile(c, "phone", "generated-password", target.ID); err == nil {
				t.Fatal("custom CA was silently dropped")
			}
		}
		if _, err := ClientURI(c, "phone", "generated-password", target.ID); err == nil {
			t.Fatal("CA lost in URI")
		}
	}
	c.TLS.CAFile = ""
	for _, target := range []string{"surge", "stash", "sing-box"} {
		if _, err := ClientURI(c, "phone", "generated-password", target); err == nil {
			t.Fatal("unsupported URI import offered")
		}
	}
	for _, password := range []string{"bad,password=other", "bad\n[Rule]\nFINAL,DIRECT", "bad\"quote"} {
		if _, _, err := ClientProfile(c, "phone", password, "surge"); err == nil {
			t.Fatal("INI injection accepted")
		}
	}
	if _, _, err := ClientProfile(c, "../escape", "generated-password", "stash"); err == nil {
		t.Fatal("invalid output name accepted")
	}
	if _, _, err := ClientProfile(c, "phone", "generated-password", "v2rayng"); err == nil {
		t.Fatal("unsupported client silently substituted")
	}
}
