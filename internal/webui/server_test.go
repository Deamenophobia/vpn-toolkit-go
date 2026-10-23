package webui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Deamenophobia/vpn-toolkit-go/internal/config"
	"github.com/Deamenophobia/vpn-toolkit-go/internal/state"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "vpn.yaml"), "127.0.0.1:8123")
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func request(t *testing.T, s *Server, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, s.origin+path, bytes.NewReader(data))
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("Authorization", "Bearer "+s.token)
	r.Header.Set("Origin", s.origin)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func readSnapshot(t *testing.T, s *Server) snapshot {
	t.Helper()
	w := request(t, s, "GET", "/api/snapshot", nil)
	if w.Code != 200 {
		t.Fatalf("snapshot status %d: %s", w.Code, w.Body.String())
	}
	var v snapshot
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v
}
func setupConfig(t *testing.T, s *Server) config.Config {
	t.Helper()
	v := readSnapshot(t, s)
	c := v.Config
	c.Server.Address = "vpn.example.com"
	c.TLS.ServerName = "vpn.example.com"
	w := request(t, s, "PUT", "/api/config", map[string]any{"config": c, "revision": v.Revision})
	if w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	return c
}

func TestAccessBoundaries(t *testing.T) {
	s := newTestServer(t)
	for _, tt := range []struct {
		name   string
		mutate func(*http.Request)
		status int
	}{
		{"no token", func(r *http.Request) { r.Header.Del("Authorization") }, 401},
		{"wrong token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer wrong") }, 401},
		{"remote peer", func(r *http.Request) { r.RemoteAddr = "192.0.2.1:5342" }, 403},
		{"dns rebinding", func(r *http.Request) { r.Host = "attacker.example:8123" }, 403},
		{"foreign origin", func(r *http.Request) { r.Header.Set("Origin", "https://attacker.example") }, 403},
		{"opaque origin", func(r *http.Request) { r.Header.Set("Origin", "null") }, 403},
		{"missing mutation origin", func(r *http.Request) { r.Header.Del("Origin") }, 403},
		{"cross site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", s.origin+"/api/devices", strings.NewReader(`{"action":"add","name":"intruder"}`))
			r.RemoteAddr = "127.0.0.1:54321"
			r.Header.Set("Authorization", "Bearer "+s.token)
			r.Header.Set("Origin", s.origin)
			r.Header.Set("Content-Type", "application/json")
			tt.mutate(r)
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != tt.status {
				t.Fatalf("status %d want %d", w.Code, tt.status)
			}
			if _, err := os.Stat(s.configPath); !os.IsNotExist(err) {
				t.Fatal("blocked request changed configuration")
			}
		})
	}
	w := request(t, s, "GET", "/", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Server settings") {
		t.Fatal("embedded UI missing")
	}
	if strings.Contains(w.Body.String(), s.token) {
		t.Fatal("public HTML exposed launch token")
	}
	if w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("missing browser protections")
	}
	for _, host := range []string{"0.0.0.0:8123", "localhost:8123", "[::]:8123", "127.0.0.1:0"} {
		if _, err := New(s.configPath, host); err == nil {
			t.Fatalf("accepted %s", host)
		}
	}
}

func TestSettingsValidationAndStaleUpdates(t *testing.T) {
	s := newTestServer(t)
	fresh := readSnapshot(t, s)
	if fresh.Configured || fresh.Revision != "missing" || fresh.Validation == "" {
		t.Fatal("new workspace claimed configured")
	}
	c := setupConfig(t, s)
	current := readSnapshot(t, s)
	if !current.Configured || current.Revision == fresh.Revision {
		t.Fatal("save was not reflected")
	}
	w := request(t, s, "PUT", "/api/config", map[string]any{"config": c, "revision": fresh.Revision})
	if w.Code != 409 {
		t.Fatalf("stale update accepted: %d", w.Code)
	}
	c.StateDir = filepath.Join(filepath.Dir(s.configPath), "elsewhere")
	w = request(t, s, "PUT", "/api/config", map[string]any{"config": c, "revision": current.Revision})
	if w.Code != 400 {
		t.Fatal("state-directory switch allowed")
	}
	c = current.Config
	c.TLS.ServerName = ""
	w = request(t, s, "PUT", "/api/config", map[string]any{"config": c, "revision": current.Revision})
	if w.Code != 400 {
		t.Fatal("invalid TLS identity saved")
	}
	c = current.Config
	c.Client.IPv6 = "tunnel"
	w = request(t, s, "PUT", "/api/config", map[string]any{"config": c, "revision": current.Revision})
	if w.Code != 200 {
		t.Fatal("valid settings rejected")
	}
	loaded, err := config.Load(s.configPath)
	if err != nil || loaded.Client.IPv6 != "tunnel" {
		t.Fatal("JSON/YAML settings mismatch")
	}
	for _, body := range []string{`{"action":"add","name":"laptop","unexpected":true}`, `{"action":"add","name":"laptop"} {}`, strings.Repeat("x", 65<<10)} {
		r := httptest.NewRequest("POST", s.origin+"/api/devices", strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:1"
		r.Header.Set("Authorization", "Bearer "+s.token)
		r.Header.Set("Origin", s.origin)
		r.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("invalid JSON accepted: %d", w.Code)
		}
	}
}

func TestDeviceExportAndRevocationWorkflow(t *testing.T) {
	s := newTestServer(t)
	c := setupConfig(t, s)
	w := request(t, s, "POST", "/api/devices", map[string]string{"action": "add", "name": "laptop"})
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var password string
	err := (state.Store{Dir: c.StateDir}).With(context.Background(), func(st *state.State) error { password = st.Devices["laptop"].Password; return nil }, false)
	if err != nil || password == "" {
		t.Fatal("missing device credential")
	}
	w = request(t, s, "GET", "/api/snapshot", nil)
	if strings.Contains(w.Body.String(), password) {
		t.Fatal("snapshot leaked credential")
	}
	if v := readSnapshot(t, s); len(v.Devices) != 1 || v.Devices[0].Name != "laptop" || v.Devices[0].Revoked {
		t.Fatal("device not visible")
	}
	w = request(t, s, "POST", "/api/exports", map[string]any{"device": "laptop", "uri": true, "qr": true})
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var result struct {
		ID    string
		Path  string
		Files []string
	}
	if err = json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(w.Body.String(), password) {
		t.Fatal("export metadata leaked credential")
	}
	for _, filename := range []string{"server.json", "laptop.mihomo.yaml", "laptop.uri.txt", "laptop.qr.png", "READY"} {
		w = request(t, s, "GET", "/api/files/"+result.ID+"/"+filename, nil)
		if w.Code != 200 || w.Header().Get("Content-Disposition") == "" {
			t.Fatalf("download failed: %s", filename)
		}
		original, err := os.ReadFile(filepath.Join(result.Path, filename))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(original, w.Body.Bytes()) {
			t.Fatal("download changed export")
		}
	}
	for _, path := range []string{"/api/files/" + result.ID + "/../state.json", "/api/files/" + result.ID + "/state.json", "/api/files/unknown/server.json"} {
		if w = request(t, s, "GET", path, nil); w.Code != 404 {
			t.Fatalf("unexpected download: %s", path)
		}
	}
	// The allowlist applies even to a file created inside the generated directory later.
	if err = os.WriteFile(filepath.Join(result.Path, "extra.txt"), []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if w = request(t, s, "GET", "/api/files/"+result.ID+"/extra.txt", nil); w.Code != 404 {
		t.Fatal("unlisted file served")
	}
	for _, action := range []string{"rotate", "revoke"} {
		w = request(t, s, "POST", "/api/devices", map[string]string{"action": action, "name": "laptop"})
		if w.Code != 200 || !strings.Contains(w.Body.String(), "restart the server") {
			t.Fatal("missing deployment boundary")
		}
	}
	if v := readSnapshot(t, s); !v.Devices[0].Revoked {
		t.Fatal("revocation not visible")
	}
	w = request(t, s, "POST", "/api/exports", map[string]any{"device": "laptop"})
	if w.Code != 400 {
		t.Fatal("revoked device exported")
	}
	// An empty client selection can still render a server with all credentials removed.
	w = request(t, s, "POST", "/api/exports", map[string]any{"device": ""})
	if w.Code != 200 {
		t.Fatal("cannot deploy final revocation")
	}
}

type launchWriter struct{ url chan string }

func (w launchWriter) Write(b []byte) (int, error) {
	if first, _, ok := strings.Cut(string(b), "\n"); ok && strings.HasPrefix(first, "Local web UI: ") {
		w.url <- strings.TrimPrefix(first, "Local web UI: ")
	}
	return len(b), nil
}
func TestRunLoopbackAndShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan string, 1)
	done := make(chan error, 1)
	go func() { done <- Run(ctx, filepath.Join(t.TempDir(), "vpn.yaml"), 0, launchWriter{started}) }()
	var launch string
	select {
	case launch = <-started:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(10 * time.Second):
		t.Fatal("UI did not start")
	}
	if !strings.HasPrefix(launch, "http://127.0.0.1:") || !strings.Contains(launch, "/#token=") {
		t.Fatal("unsafe launch address")
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Get(launch)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(fmt.Sprint(resp.StatusCode))
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("UI did not stop")
	}
}

func TestClientSelectionAndQRAccess(t *testing.T) {
	s := newTestServer(t)
	setupConfig(t, s)
	v := readSnapshot(t, s)
	found := false
	for _, client := range v.Clients {
		if client.ID == "shadowrocket" {
			found = true
			if !client.RequiredURI || client.Scope != "connection-only" {
				t.Fatal("wrong client capabilities")
			}
		}
	}
	if !found {
		t.Fatal("client catalogue missing")
	}
	if w := request(t, s, "POST", "/api/devices", map[string]string{"action": "add", "name": "phone"}); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	w := request(t, s, "POST", "/api/exports", map[string]any{"device": "phone", "client": "shadowrocket", "qr": true})
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var result struct {
		ID    string
		Files []string
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	files := strings.Join(result.Files, " ")
	if !strings.Contains(files, "phone.uri.txt") || !strings.Contains(files, "phone.qr.png") || strings.Contains(files, "mihomo.yaml") {
		t.Fatal("wrong client export")
	}
	r := httptest.NewRequest("GET", s.origin+"/api/files/"+result.ID+"/phone.qr.png", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("QR accessible without launch token")
	}
	w = request(t, s, "POST", "/api/exports", map[string]string{"client": "unsupported"})
	if w.Code != 400 {
		t.Fatal("unsupported app silently accepted")
	}
}
