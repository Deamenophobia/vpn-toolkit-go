package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIWorkflowAndOverrides(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "vpn.yaml")
	var output bytes.Buffer
	var password string
	call := func(args ...string) {
		t.Helper()
		output.Reset()
		if err := run(args, &output); err != nil {
			t.Fatal(err)
		}
		if password != "" && strings.Contains(output.String(), password) {
			t.Fatal("credential leaked in CLI output")
		}
	}
	call("init", "--config", p, "--server", "vpn.example.com")
	call("config", "--config", p, "--port", "8443")
	if !strings.Contains(output.String(), "port: 8443") {
		t.Fatal("flag did not override file")
	}
	call("client", "add", "--config", p, "--name", "laptop")
	data, err := os.ReadFile(filepath.Join(root, "private", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var persisted struct {
		Devices map[string]struct{ Password string }
	}
	if err = json.Unmarshal(data, &persisted); err != nil {
		t.Fatal(err)
	}
	password = persisted.Devices["laptop"].Password
	if password == "" {
		t.Fatal("missing persisted credential")
	}
	call("client", "list", "--config", p)
	if !strings.Contains(output.String(), "laptop") {
		t.Fatal("missing device")
	}
	call("render", "--config", p, "--out", filepath.Join(root, "bundle"))
	call("config", "--config", p)
	if run([]string{"init", "--config", p, "--server", "other.example.com"}, &output) == nil {
		t.Fatal("overwrote config")
	}
}

func TestUIOptions(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"ui", "--help"}, &out); err != nil || !strings.Contains(out.String(), "--ui-port") {
		t.Fatal("UI help missing")
	}
	for _, args := range [][]string{{"ui", "--server", "vpn.example.com"}, {"ui", "--ui-port", "-1"}} {
		if err := run(args, &out); err == nil {
			t.Fatal("invalid UI options accepted")
		}
	}
}

func TestShadowrocketCLIExport(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "vpn.yaml")
	out := filepath.Join(root, "phone-bundle")
	var buf bytes.Buffer
	for _, args := range [][]string{{"clients"}, {"init", "--config", path, "--server", "vpn.example.com"}, {"client", "add", "--config", path, "--name", "phone"}, {"render", "--config", path, "--out", out, "--name", "phone", "--client", "shadowrocket", "--qr"}} {
		if err := run(args, &buf); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(buf.String(), "Shadowrocket") || !strings.Contains(buf.String(), "connection-only") {
		t.Fatal("client instructions missing")
	}
	for _, name := range []string{"phone.uri.txt", "phone.qr.png", "IMPORT.txt"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Fatal(err)
		}
	}
}
