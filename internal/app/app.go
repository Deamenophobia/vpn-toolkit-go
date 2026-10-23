package app

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Deamenophobia/vpn-toolkit-go/internal/config"
	"github.com/Deamenophobia/vpn-toolkit-go/internal/engine"
	exporter "github.com/Deamenophobia/vpn-toolkit-go/internal/export"
	"github.com/Deamenophobia/vpn-toolkit-go/internal/host"
	"github.com/Deamenophobia/vpn-toolkit-go/internal/privatefs"
	"github.com/Deamenophobia/vpn-toolkit-go/internal/state"
	qrcode "github.com/skip2/go-qrcode"
	"os"
	"path/filepath"
	"sort"
)

type App struct {
	Config config.Config
	Engine engine.Adapter
}
type RenderOptions struct {
	Out, Device, Client string
	URI, QR             bool
}
type DeviceInfo struct {
	Name    string
	Revoked bool
}

func New(c config.Config) *App { return &App{Config: c, Engine: engine.AnyTLS{}} }
func (a *App) Change(ctx context.Context, action, name string) error {
	return (state.Store{Dir: a.Config.StateDir}).With(ctx, func(s *state.State) error { return state.Change(s, action, name) }, true)
}
func (a *App) List(ctx context.Context) ([]DeviceInfo, uint64, error) {
	var list []DeviceInfo
	var rev uint64
	err := (state.Store{Dir: a.Config.StateDir}).With(ctx, func(s *state.State) error {
		rev = s.Revision
		for n, d := range s.Devices {
			list = append(list, DeviceInfo{n, d.Revoked})
		}
		return nil
	}, false)
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list, rev, err
}
func (a *App) Render(ctx context.Context, o RenderOptions) error {
	target, err := exporter.ClientTarget(o.Client)
	if err != nil {
		return err
	}
	if err = target.Validate(a.Config, o.URI, o.QR); err != nil {
		return err
	}
	if o.Out == "" {
		return errors.New("choose a new private output directory with --out")
	}
	out, err := filepath.Abs(o.Out)
	if err != nil {
		return err
	}
	if _, err = os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
		return errors.New("output directory already exists or cannot be checked; choose a new directory")
	}
	// Hold the state lock until the snapshot has been fully exported.
	return (state.Store{Dir: a.Config.StateDir}).With(ctx, func(s *state.State) error {
		files := map[string][]byte{}
		server, err := a.Engine.Render(a.Config, *s)
		if err != nil {
			return err
		}
		files["server.json"] = server
		files["vpn-toolkit.service"] = []byte(host.Service)
		files["IMPORT.txt"] = target.Instructions()
		names := []string{}
		for n, d := range s.Devices {
			if !d.Revoked && (o.Device == "" || n == o.Device) {
				names = append(names, n)
			}
		}
		if o.Device != "" && len(names) == 0 {
			return errors.New("active device not found")
		}
		sort.Strings(names)
		for _, n := range names {
			d := s.Devices[n]
			filename, profile, err := exporter.ClientProfile(a.Config, n, d.Password, target.ID)
			if err != nil {
				return err
			}
			files[filename] = profile
			if o.URI || o.QR {
				uri, err := exporter.ClientURI(a.Config, n, d.Password, target.ID)
				if err != nil {
					return err
				}
				if o.URI {
					files[n+".uri.txt"] = []byte(uri + "\n")
				}
				if o.QR {
					png, err := qrcode.Encode(uri, qrcode.Medium, 320)
					if err != nil {
						return errors.New("connection URI is too large for QR export")
					}
					files[n+".qr.png"] = png
				}
			}
		}
		clientEngine := "application-defined; see IMPORT.txt"
		if target.ID == "mihomo" {
			clientEngine = "mihomo " + engine.MihomoVersion
		}
		if target.ID == "sing-box" {
			clientEngine = "sing-box " + engine.SingBoxVersion
		}
		manifest, _ := json.MarshalIndent(map[string]any{"schema": 1, "state_revision": s.Revision, "devices": names, "client_engine": clientEngine,
			"server_engine": "sing-box " + engine.SingBoxVersion, "client_target": target.ID, "client_format": target.Format, "client_scope": target.Scope,
			"uri_scope":         "connection-only",
			"client_gui_status": "not_tested", "tested_engine_pair": "sing-box " + engine.SingBoxVersion + " / mihomo " + engine.MihomoVersion,
			"deployment_status": "not_applied", "note": "Restart the server with this configuration to apply credential changes and end existing sessions."}, "", "  ")
		files["manifest.json"] = append(manifest, '\n')
		if err = os.Mkdir(out, 0700); err != nil {
			return err
		}
		if err = privatefs.Dir(out); err != nil {
			return err
		}
		keys := make([]string, 0, len(files))
		for n := range files {
			keys = append(keys, n)
		}
		sort.Strings(keys)
		for _, n := range keys {
			if err = privatefs.Write(filepath.Join(out, n), files[n]); err != nil {
				return errors.New("export incomplete; do not deploy this directory")
			}
		}
		return privatefs.Write(filepath.Join(out, "READY"), []byte("Generated configuration only; runtime validation and deployment are still required.\n"))
	}, false)
}
