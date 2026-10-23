package export

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"github.com/Deamenophobia/vpn-toolkit-go/internal/config"
	"go.yaml.in/yaml/v3"
	"net"
	"net/url"
	"os"
	"strconv"
	"time"
)

// CAFingerprint accepts a CA, never a leaf pin that could bypass name checks.
func CAFingerprint(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("cannot read tls.ca_file")
	}
	block, rest := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("tls.ca_file must contain a PEM CA certificate")
	}
	if next, _ := pem.Decode(rest); next != nil {
		return "", errors.New("tls.ca_file must contain exactly one CA certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA || !cert.BasicConstraintsValid {
		return "", errors.New("tls.ca_file must be a CA certificate, not a leaf certificate")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return "", errors.New("CA certificate is outside its validity period")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}
func Mihomo(c config.Config, name, password string) ([]byte, error) {
	pin, err := CAFingerprint(c.TLS.CAFile)
	if err != nil {
		return nil, err
	}
	p := map[string]any{"name": "vpn", "type": "anytls", "server": c.Server.Address, "port": c.Server.Port,
		"password": password, "udp": c.Client.UDP, "sni": c.TLS.ServerName, "skip-cert-verify": false}
	if pin != "" {
		p["fingerprint"] = pin
	}
	rules := []string{}
	if c.Client.IPv6 == "block" {
		rules = append(rules, "IP-CIDR6,::/0,REJECT,no-resolve")
	}
	for _, cidr := range c.Client.DirectCIDRs {
		kind := "IP-CIDR"
		if ip, _, _ := net.ParseCIDR(cidr); ip.To4() == nil {
			kind = "IP-CIDR6"
		}
		rules = append(rules, kind+","+cidr+",DIRECT,no-resolve")
	}
	rules = append(rules, "MATCH,vpn")
	nameservers := make([]string, len(c.Client.DNS))
	for i, s := range c.Client.DNS {
		nameservers[i] = s + "#vpn"
	}
	out := map[string]any{
		"mixed-port": c.Client.MixedPort, "bind-address": "127.0.0.1", "allow-lan": false,
		"mode": "rule", "log-level": "warning", "ipv6": true,
		"proxies": []any{p}, "rules": rules,
		"dns": map[string]any{"enable": true, "listen": net.JoinHostPort("127.0.0.1", strconv.Itoa(c.Client.DNSListenPort)),
			"ipv6": c.Client.IPv6 == "tunnel", "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
			"nameserver": nameservers, "proxy-server-nameserver": c.Client.BootstrapDNS,
			"default-nameserver": c.Client.BootstrapDNS},
		"tun": map[string]any{"enable": c.Client.Mode == "tun", "stack": "mixed", "auto-route": true,
			"auto-detect-interface": true, "strict-route": true, "dns-hijack": []string{"any:53", "tcp://any:53"},
			"inet6-address": []string{"fdfe:dcba:9876::1/126"}},
	}
	b, err := yaml.Marshal(out)
	return append([]byte("# Private client profile: "+name+"\n# Requires the documented TUN and IPv6 checks before full-device use.\n"), b...), err
}
func URI(c config.Config, name, password string) (string, error) {
	if c.TLS.CAFile != "" {
		return "", errors.New("standard AnyTLS URI cannot carry the custom CA trust setting; export Mihomo YAML instead")
	}
	u := url.URL{Scheme: "anytls", User: url.User(password), Host: net.JoinHostPort(c.Server.Address, strconv.Itoa(c.Server.Port)), Path: "/", Fragment: name}
	q := url.Values{"sni": []string{c.TLS.ServerName}, "insecure": []string{"0"}}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
