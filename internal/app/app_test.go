package app

import (
	"context"
	"encoding/json"
	"github.com/Deamenophobia/vpn-toolkit-go/internal/config"
	exporter "github.com/Deamenophobia/vpn-toolkit-go/internal/export"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportSnapshotAndRevocation(t *testing.T) {
	root := t.TempDir()
	c := config.Defaults()
	c.StateDir = filepath.Join(root, "state")
	c.Server.Address = "vpn.example.com"
	c.TLS.ServerName = c.Server.Address
	a := New(c)
	ctx := context.Background()
	if err := a.Change(ctx, "add", "laptop"); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	if err := a.Render(ctx, RenderOptions{Out: first, URI: true, QR: true}); err != nil {
		t.Fatal(err)
	}
	if err := a.Render(ctx, RenderOptions{Out: second}); err != nil {
		t.Fatal(err)
	}
	b1, _ := os.ReadFile(filepath.Join(first, "server.json"))
	b2, _ := os.ReadFile(filepath.Join(second, "server.json"))
	if string(b1) != string(b2) {
		t.Fatal("render rotated credentials or was not deterministic")
	}
	if err := a.Render(ctx, RenderOptions{Out: first}); err == nil {
		t.Fatal("overwrote existing export")
	}
	png, _ := os.ReadFile(filepath.Join(first, "laptop.qr.png"))
	if len(png) < 8 || string(png[:8]) != "\x89PNG\r\n\x1a\n" {
		t.Fatal("QR is not PNG")
	}
	uri, _ := os.ReadFile(filepath.Join(first, "laptop.uri.txt"))
	if !strings.Contains(string(uri), "insecure=0") {
		t.Fatal("unsafe URI")
	}
	profile, _ := os.ReadFile(filepath.Join(first, "laptop.mihomo.yaml"))
	if !strings.Contains(string(profile), "skip-cert-verify: false") {
		t.Fatal("unsafe TLS")
	}
	if err := a.Change(ctx, "revoke", "laptop"); err != nil {
		t.Fatal(err)
	}
	third := filepath.Join(root, "third")
	if err := a.Render(ctx, RenderOptions{Out: third}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(third, "laptop.mihomo.yaml")); !os.IsNotExist(err) {
		t.Fatal("exported revoked device")
	}
	manifest, _ := os.ReadFile(filepath.Join(third, "manifest.json"))
	if !strings.Contains(string(manifest), "not_applied") {
		t.Fatal("implied deployment")
	}
}

func TestTargetedExportsDoNotRotateOrMixClientFormats(t *testing.T) {
	c := config.Defaults()
	c.Server.Address = "vpn.example.com"
	c.TLS.ServerName = c.Server.Address
	c.StateDir = filepath.Join(t.TempDir(), "private")
	a := New(c)
	ctx := context.Background()
	for _, name := range []string{"phone", "other"} {
		if err := a.Change(ctx, "add", name); err != nil {
			t.Fatal(err)
		}
	}
	root := t.TempDir()
	var expectedServer []byte
	for _, target := range exporter.Targets() {
		out := filepath.Join(root, target.ID)
		if err := a.Render(ctx, RenderOptions{Out: out, Device: "phone", Client: target.ID, QR: target.RequiredURI}); err != nil {
			t.Fatal(err)
		}
		server, err := os.ReadFile(filepath.Join(out, "server.json"))
		if err != nil {
			t.Fatal(err)
		}
		if expectedServer == nil {
			expectedServer = server
		} else if string(expectedServer) != string(server) {
			t.Fatal("changing client target changed server credentials")
		}
		entries, err := os.ReadDir(out)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "other.") {
				t.Fatal("another device's client file exported")
			}
		}
		if target.ID != "mihomo" {
			if _, err = os.Stat(filepath.Join(out, "phone.mihomo.yaml")); !os.IsNotExist(err) {
				t.Fatal("wrong client format mixed into bundle")
			}
		}
		if target.RequiredURI {
			if _, err = os.Stat(filepath.Join(out, "phone.uri.txt")); err != nil {
				t.Fatal("URL target did not generate its URL by default")
			}
		}
		manifest, err := os.ReadFile(filepath.Join(out, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err = json.Unmarshal(manifest, &m); err != nil {
			t.Fatal(err)
		}
		if m["client_target"] != target.ID || m["client_scope"] != target.Scope || m["client_gui_status"] != "not_tested" {
			t.Fatal("manifest misrepresents compatibility")
		}
	}
	invalid := filepath.Join(root, "invalid")
	if err := a.Render(ctx, RenderOptions{Out: invalid, Client: "unknown"}); err == nil {
		t.Fatal("invalid client allowed")
	}
	if _, err := os.Stat(invalid); !os.IsNotExist(err) {
		t.Fatal("invalid selection left a bundle")
	}
}
