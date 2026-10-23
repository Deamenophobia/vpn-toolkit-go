// Package webui is an optional loopback-only interface to the existing app.
package webui

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Deamenophobia/vpn-toolkit-go/internal/app"
	"github.com/Deamenophobia/vpn-toolkit-go/internal/config"
	exporter "github.com/Deamenophobia/vpn-toolkit-go/internal/export"
	"github.com/Deamenophobia/vpn-toolkit-go/internal/privatefs"
)

//go:embed assets/*
var assets embed.FS

type bundle struct {
	dir   string
	files map[string]bool
}
type Server struct {
	configPath, host, origin, token string
	mu                              sync.Mutex
	bundles                         map[string]bundle
}
type device struct {
	Name    string `json:"name"`
	Revoked bool   `json:"revoked"`
}
type snapshot struct {
	Config        config.Config     `json:"config"`
	Revision      string            `json:"config_revision"`
	StateRevision uint64            `json:"state_revision"`
	Devices       []device          `json:"devices"`
	Configured    bool              `json:"configured"`
	Validation    string            `json:"validation"`
	Clients       []exporter.Target `json:"clients"`
}

func New(path, host string) (*Server, error) {
	ip, port, err := net.SplitHostPort(host)
	if err != nil || ip != "127.0.0.1" {
		return nil, errors.New("web UI must listen on 127.0.0.1")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return nil, errors.New("invalid UI port")
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return nil, err
	}
	return &Server{configPath: path, host: host, origin: "http://" + host, token: hex.EncodeToString(b), bundles: map[string]bundle{}}, nil
}
func (s *Server) URL() string { return s.origin + "/#token=" + s.token }

func Run(ctx context.Context, path string, port int, out io.Writer) error {
	if port < 0 || port > 65535 {
		return errors.New("UI port must be between 0 and 65535")
	}
	ln, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("start local UI: %w", err)
	}
	defer ln.Close()
	s, err := New(path, ln.Addr().String())
	if err != nil {
		return err
	}
	httpServer := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	fmt.Fprintf(out, "Local web UI: %s\nKeep this launch link private. Press Ctrl+C to stop.\n", s.URL())
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			httpServer.Shutdown(shutdown)
		case <-stopped:
		}
	}()
	err = httpServer.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || net.ParseIP(ip) == nil || !net.ParseIP(ip).IsLoopback() || r.Host != s.host {
			http.Error(w, "Local access only", http.StatusForbidden)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.token)) != 1 {
				problem(w, 401, "Open the private launch link printed by vpnctl.")
				return
			}
			origin := r.Header.Get("Origin")
			if (origin != "" && origin != s.origin) || (r.Method != http.MethodGet && origin != s.origin) {
				problem(w, 403, "This action must come from the local UI.")
				return
			}
			if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
				problem(w, 403, "Cross-site requests are not allowed.")
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
			defer cancel()
			s.mu.Lock()
			defer s.mu.Unlock()
			s.api(w, r.WithContext(ctx))
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", 405)
			return
		}
		path := r.URL.Path
		if path == "/" {
			path = "/index.html"
		}
		if path != "/index.html" && path != "/app.js" && path != "/style.css" {
			http.NotFound(w, r)
			return
		}
		data, err := assets.ReadFile("assets" + path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", mime.TypeByExtension(filepath.Ext(path)))
		w.Write(data)
	})
}
func respond(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
func problem(w http.ResponseWriter, status int, message string) {
	respond(w, status, map[string]string{"error": message})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	kind, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || kind != "application/json" {
		problem(w, 415, "Send JSON from the local UI.")
		return false
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		problem(w, 400, "Invalid request fields.")
		return false
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		problem(w, 400, "Expected one JSON object.")
		return false
	}
	return true
}
func (s *Server) readConfig() (config.Config, string, error) {
	data, err := os.ReadFile(s.configPath)
	if errors.Is(err, os.ErrNotExist) {
		c := config.Defaults()
		c.StateDir = filepath.Join(filepath.Dir(s.configPath), c.StateDir)
		return c, "missing", nil
	}
	if err != nil {
		return config.Config{}, "", errors.New("Cannot read the selected configuration file.")
	}
	c, err := config.Parse(data, s.configPath)
	sum := sha256.Sum256(data)
	return c, hex.EncodeToString(sum[:]), err
}
func (s *Server) api(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/files/") {
		s.download(w, r)
		return
	}
	c, revision, err := s.readConfig()
	if err != nil {
		problem(w, 400, err.Error())
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/snapshot" {
		result := snapshot{Config: c, Revision: revision, Devices: []device{}, Clients: exporter.Targets()}
		if err = c.Validate(); err != nil {
			result.Validation = err.Error()
		} else {
			result.Configured = true
			items, rev, e := app.New(c).List(r.Context())
			if e != nil {
				problem(w, 500, "Cannot read private device state.")
				return
			}
			result.StateRevision = rev
			for _, d := range items {
				result.Devices = append(result.Devices, device{d.Name, d.Revoked})
			}
		}
		respond(w, 200, result)
		return
	}
	if r.Method == http.MethodPut && r.URL.Path == "/api/config" {
		var input struct {
			Config   config.Config `json:"config"`
			Revision string        `json:"revision"`
		}
		if !decode(w, r, &input) {
			return
		}
		if input.Revision != revision {
			problem(w, 409, "Settings changed elsewhere. Reload before saving.")
			return
		}
		// Moving state from a browser could silently switch the set of devices.
		if input.Config.StateDir != c.StateDir {
			problem(w, 400, "Change the state directory in the configuration file while the UI is stopped.")
			return
		}
		if err = input.Config.Validate(); err != nil {
			problem(w, 400, err.Error())
			return
		}
		data, err := config.Marshal(input.Config)
		if err != nil {
			problem(w, 500, "Cannot encode configuration.")
			return
		}
		if err = privatefs.Write(s.configPath, data); err != nil {
			problem(w, 500, "Cannot save the selected configuration file.")
			return
		}
		respond(w, 200, map[string]string{"message": "Settings saved locally. Generate and deploy new server files to apply them."})
		return
	}
	if err = c.Validate(); err != nil {
		problem(w, 400, "Complete and save valid server settings first.")
		return
	}
	a := app.New(c)
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/devices":
		var input struct {
			Action string `json:"action"`
			Name   string `json:"name"`
		}
		if !decode(w, r, &input) {
			return
		}
		if input.Action != "add" && input.Action != "rotate" && input.Action != "revoke" {
			problem(w, 400, "Unknown device action.")
			return
		}
		if err = a.Change(r.Context(), input.Action, input.Name); err != nil {
			problem(w, 400, err.Error())
			return
		}
		respond(w, 200, map[string]string{"message": "Device settings updated locally. Generate files and restart the server with the new configuration to apply the change."})
	case r.Method == http.MethodPost && r.URL.Path == "/api/exports":
		var input struct {
			Device string `json:"device"`
			Client string `json:"client"`
			URI    bool   `json:"uri"`
			QR     bool   `json:"qr"`
		}
		if !decode(w, r, &input) {
			return
		}
		idBytes := make([]byte, 8)
		if _, err = rand.Read(idBytes); err != nil {
			problem(w, 500, "Cannot create export identifier.")
			return
		}
		id := time.Now().UTC().Format("20060102-150405") + "-" + hex.EncodeToString(idBytes)
		root := filepath.Join(c.StateDir, "exports")
		if err = privatefs.Dir(root); err != nil {
			problem(w, 500, "Cannot create private export directory.")
			return
		}
		path := filepath.Join(root, id)
		if err = a.Render(r.Context(), app.RenderOptions{Out: path, Device: input.Device, Client: input.Client, URI: input.URI, QR: input.QR}); err != nil {
			problem(w, 400, err.Error())
			return
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			problem(w, 500, "Cannot inspect generated files.")
			return
		}
		files := []string{}
		allowed := map[string]bool{}
		for _, e := range entries {
			if !e.IsDir() {
				files = append(files, e.Name())
				allowed[e.Name()] = true
			}
		}
		sort.Strings(files)
		s.bundles[id] = bundle{dir: path, files: allowed}
		respond(w, 200, map[string]any{"id": id, "path": path, "files": files, "message": "Files generated. Deployment is still pending."})
	default:
		problem(w, 404, "Unknown local UI operation.")
	}
}
func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/files/"), "/")
	if len(parts) != 2 {
		problem(w, 404, "Unknown export.")
		return
	}
	b, ok := s.bundles[parts[0]]
	if !ok || !b.files[parts[1]] {
		problem(w, 404, "Unknown export file.")
		return
	}
	data, err := privatefs.Read(filepath.Join(b.dir, parts[1]))
	if err != nil {
		problem(w, 500, "Cannot read export file.")
		return
	}
	kind := mime.TypeByExtension(filepath.Ext(parts[1]))
	if kind == "" {
		kind = "application/octet-stream"
	}
	w.Header().Set("Content-Type", kind)
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": parts[1]}))
	w.Write(data)
}
