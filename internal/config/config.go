package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

type Config struct {
	Version  int    `yaml:"version" json:"version"`
	Engine   string `yaml:"engine" json:"engine"`
	StateDir string `yaml:"state_dir" json:"state_dir"`
	Server   Server `yaml:"server" json:"server"`
	TLS      TLS    `yaml:"tls" json:"tls"`
	Client   Client `yaml:"client" json:"client"`
}
type Server struct {
	Address  string `yaml:"address" json:"address"`
	Port     int    `yaml:"port" json:"port"`
	Listen   string `yaml:"listen" json:"listen"`
	DNS      string `yaml:"dns" json:"dns"`
	LogLevel string `yaml:"log_level" json:"log_level"`
}
type TLS struct {
	ServerName  string `yaml:"server_name" json:"server_name"`
	Certificate string `yaml:"certificate" json:"certificate"`
	Key         string `yaml:"key" json:"key"`
	CAFile      string `yaml:"ca_file,omitempty" json:"ca_file"`
}
type Client struct {
	Mode          string   `yaml:"mode" json:"mode"`
	MixedPort     int      `yaml:"mixed_port" json:"mixed_port"`
	DNSListenPort int      `yaml:"dns_listen_port" json:"dns_listen_port"`
	IPv6          string   `yaml:"ipv6" json:"ipv6"`
	DNS           []string `yaml:"dns" json:"dns"`
	BootstrapDNS  []string `yaml:"bootstrap_dns" json:"bootstrap_dns"`
	DirectCIDRs   []string `yaml:"direct_cidrs,omitempty" json:"direct_cidrs"`
	UDP           bool     `yaml:"udp" json:"udp"`
}

func Defaults() Config {
	return Config{
		Version: 1, Engine: "sing-box-anytls", StateDir: "private",
		Server: Server{Port: 443, Listen: "0.0.0.0", DNS: "1.1.1.1", LogLevel: "warn"},
		TLS:    TLS{Certificate: "/etc/vpn-toolkit/tls/fullchain.pem", Key: "/etc/vpn-toolkit/tls/privkey.pem"},
		Client: Client{Mode: "tun", MixedPort: 7890, DNSListenPort: 1053, IPv6: "block", UDP: true,
			DNS: []string{"https://1.1.1.1/dns-query"}, BootstrapDNS: []string{"https://1.1.1.1/dns-query"}},
	}
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Defaults(), fmt.Errorf("read config: %w", err)
	}
	return Parse(data, path)
}

// Parse uses path as the base for local references, without reading it again.
func Parse(data []byte, path string) (Config, error) {
	c := Defaults()
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	if err := d.Decode(&c); err != nil {
		return c, errors.New("invalid YAML or unknown configuration field; see docs/CONFIGURATION.md")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("configuration must contain exactly one YAML document")
	}
	base, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return c, err
	}
	if c.StateDir != "" {
		c.StateDir = resolve(base, c.StateDir)
	}
	if c.TLS.CAFile != "" {
		c.TLS.CAFile = resolve(base, c.TLS.CAFile)
	}
	// Server certificate/key paths belong to the target server, not this workstation.
	return c, nil
}
func resolve(base, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(base, p)
}
func Name(s string) bool {
	return regexp.MustCompile("^[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}$").MatchString(s)
}
func Host(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, p := range strings.Split(strings.TrimSuffix(s, "."), ".") {
		if len(p) == 0 || len(p) > 63 || !regexp.MustCompile("^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$").MatchString(p) {
			return false
		}
	}
	return true
}
func (c Config) Validate() error {
	if c.Version != 1 {
		return errors.New("unsupported config version; expected 1")
	}
	if c.Engine != "sing-box-anytls" {
		return errors.New("supported engine: sing-box-anytls")
	}
	if !Host(c.Server.Address) || !Host(c.TLS.ServerName) {
		return errors.New("server.address and tls.server_name must be hostnames or IP addresses")
	}
	if net.ParseIP(c.Server.Listen) == nil {
		return errors.New("server.listen must be an IP address")
	}
	if net.ParseIP(c.Server.DNS) == nil {
		return errors.New("server.dns must be a resolver IP address")
	}
	for _, p := range []int{c.Server.Port, c.Client.MixedPort, c.Client.DNSListenPort} {
		if p < 1 || p > 65535 {
			return errors.New("ports must be between 1 and 65535")
		}
	}
	if c.Client.MixedPort == c.Client.DNSListenPort {
		return errors.New("client proxy and DNS ports must differ")
	}
	if c.StateDir == "" || c.TLS.Certificate == "" || c.TLS.Key == "" {
		return errors.New("state_dir and server certificate/key paths are required")
	}
	if strings.ContainsAny(c.TLS.Certificate+c.TLS.Key, "\r\n\x00") {
		return errors.New("invalid certificate/key path")
	}
	if c.TLS.Certificate == c.TLS.Key {
		return errors.New("certificate and key paths must differ")
	}
	if c.Client.Mode != "tun" && c.Client.Mode != "proxy" {
		return errors.New("client.mode must be tun or proxy")
	}
	if c.Client.IPv6 != "block" && c.Client.IPv6 != "tunnel" {
		return errors.New("client.ipv6 must be block or tunnel")
	}
	if c.Server.LogLevel != "warn" && c.Server.LogLevel != "error" && c.Server.LogLevel != "info" {
		return errors.New("server.log_level must be warn, error, or info")
	}
	if len(c.Client.DNS) == 0 || len(c.Client.BootstrapDNS) == 0 {
		return errors.New("client DNS and bootstrap DNS lists must not be empty")
	}
	for index, list := range [][]string{c.Client.DNS, c.Client.BootstrapDNS} {
		for _, s := range list {
			// Keep the first adapter's DNS grammar narrow; fragments can override routing.
			if !strings.HasPrefix(s, "https://") || strings.ContainsAny(s, "#\r\n\x00") {
				return errors.New("client DNS values must be HTTPS resolver URLs without routing fragments")
			}
			u, err := url.Parse(s)
			if err != nil || u.Hostname() == "" || u.User != nil || !Host(u.Hostname()) {
				return errors.New("invalid HTTPS resolver URL")
			}
			if index == 1 && net.ParseIP(u.Hostname()) == nil {
				return errors.New("bootstrap DNS URLs must use an IP address to avoid DNS bootstrap loops")
			}
		}
	}
	for _, s := range c.Client.DirectCIDRs {
		if _, err := netip.ParsePrefix(s); err != nil {
			return errors.New("client.direct_cidrs must contain CIDR prefixes")
		}
	}
	return nil
}
func Marshal(c Config) ([]byte, error) { return yaml.Marshal(c) }
