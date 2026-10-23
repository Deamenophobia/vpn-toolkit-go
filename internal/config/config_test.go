package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDefaultsAndRejectUnsafeInput(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "vpn.yaml")
	valid := "version: 1\nserver:\n  address: vpn.example.com\ntls:\n  server_name: vpn.example.com\n"
	if err := os.WriteFile(p, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Server.Port != 443 || !c.Client.UDP || c.StateDir != filepath.Join(dir, "private") {
		t.Fatal("defaults/path resolution failed")
	}
	for _, tail := range []string{
		"unknown_secret: do-not-echo-me\n",
		"---\nserver: {}\n",
		"client:\n  dns: []\n",
		"client:\n  bootstrap_dns: [https://resolver.example/dns-query]\n",
		"client:\n  dns: [https://1.1.1.1/dns-query#DIRECT]\n",
		"state_dir: ''\n",
	} {
		os.WriteFile(p, []byte(valid+tail), 0600)
		c, err = Load(p)
		if err == nil {
			err = c.Validate()
		}
		if err == nil {
			t.Fatalf("accepted invalid config %q", tail)
		}
		if strings.Contains(err.Error(), "do-not-echo-me") {
			t.Fatal("input leaked in error")
		}
	}
}
func TestListReplacement(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vpn.yaml")
	os.WriteFile(p, []byte("client:\n  dns: [https://8.8.8.8/dns-query]\n"), 0600)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Client.DNS) != 1 || c.Client.DNS[0] != "https://8.8.8.8/dns-query" {
		t.Fatal("lists must replace defaults")
	}
}
