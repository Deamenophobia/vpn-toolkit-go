package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/Deamenophobia/vpn-toolkit-go/internal/app"
	"github.com/Deamenophobia/vpn-toolkit-go/internal/config"
	"github.com/Deamenophobia/vpn-toolkit-go/internal/engine"
	exporter "github.com/Deamenophobia/vpn-toolkit-go/internal/export"
	"github.com/Deamenophobia/vpn-toolkit-go/internal/host"
	"github.com/Deamenophobia/vpn-toolkit-go/internal/privatefs"
	"github.com/Deamenophobia/vpn-toolkit-go/internal/webui"
)

const usage = "vpnctl init | config | client add|list|rotate|revoke | clients | render | check | ui | version\n" +
	"Common flags: --config vpn.yaml, --server HOST, --port PORT, --tls-name NAME, --mode tun|proxy\n" +
	"init:   [--server HOST] [--tls-name NAME] writes a new configuration\n" +
	"config: displays effective settings (no credentials)\n" +
	"client: --name DEVICE for add, rotate, revoke\n" +
	"clients: lists client export targets and import scope\n" +
	"render: --out NEW_DIRECTORY [--name DEVICE] [--client TARGET] [--uri] [--qr]\n" +
	"check:  --kind server|client|sing-box-client --file CONFIG --binary ENGINE_EXECUTABLE\n" +
	"ui:     [--config vpn.yaml] [--ui-port PORT] starts the local web interface\n" +
	"All flags follow the command and subcommand. See README.md for the first connection.\n"

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
func run(args []string, w io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		fmt.Fprint(w, usage)
		return nil
	}
	command := args[0]
	args = args[1:]
	action := ""
	if command == "client" {
		if len(args) == 0 {
			return errors.New("client requires add, list, rotate or revoke")
		}
		action = args[0]
		args = args[1:]
	}
	if command == "version" {
		fmt.Fprintf(w, "vpnctl 0.1.0-dev; tested engines: sing-box %s, mihomo %s\n", engine.SingBoxVersion, engine.MihomoVersion)
		return nil
	}
	if command == "clients" {
		if len(args) != 0 {
			return errors.New("clients takes no arguments")
		}
		for _, target := range exporter.Targets() {
			fmt.Fprintf(w, "%s\t%s\t%s\n  %s\n", target.ID, target.Label, target.Scope, target.Note)
		}
		return nil
	}
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	path := f.String("config", "vpn.yaml", "configuration file")
	address := f.String("server", "", "server address")
	port := f.Int("port", 0, "server port")
	tlsName := f.String("tls-name", "", "server certificate identity")
	mode := f.String("mode", "", "client routing mode")
	name := f.String("name", "", "device name")
	out := f.String("out", "", "new output directory")
	uri := f.Bool("uri", false, "export connection URI")
	qr := f.Bool("qr", false, "export QR image")
	kind := f.String("kind", "", "native configuration kind")
	file := f.String("file", "", "native configuration file")
	binary := f.String("binary", "", "engine executable")
	uiPort := f.Int("ui-port", 0, "local UI port; zero selects an available port")
	clientTarget := f.String("client", "mihomo", "client export target; see vpnctl clients")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(w, usage)
			return nil
		}
		return errors.New("invalid command options; run vpnctl help")
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments; use --name for device names")
	}
	if command == "ui" {
		unsupported := false
		f.Visit(func(v *flag.Flag) {
			if v.Name != "config" && v.Name != "ui-port" {
				unsupported = true
			}
		})
		if unsupported {
			return errors.New("ui accepts only --config and --ui-port; edit settings in the UI")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return webui.Run(ctx, *path, *uiPort, w)
	}
	var c config.Config
	var err error
	if command == "init" {
		c = config.Defaults()
	} else {
		c, err = config.Load(*path)
		if err != nil {
			return err
		}
	}
	f.Visit(func(v *flag.Flag) {
		switch v.Name {
		case "server":
			c.Server.Address = *address
		case "port":
			c.Server.Port = *port
		case "tls-name":
			c.TLS.ServerName = *tlsName
		case "mode":
			c.Client.Mode = *mode
		}
	})
	if command == "init" && c.TLS.ServerName == "" {
		c.TLS.ServerName = c.Server.Address
	}
	if err = c.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a := app.New(c)
	switch command {
	case "init":
		data, err := config.Marshal(c)
		if err != nil {
			return err
		}
		dest, err := os.OpenFile(*path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return errors.New("cannot create config; choose an existing parent directory and an unused filename")
		}
		if _, err = dest.Write(data); err != nil {
			dest.Close()
			return err
		}
		if err = dest.Close(); err != nil {
			return err
		}
		fmt.Fprintln(w, "Configuration created. Set certificate paths and review routing before exporting.")
	case "config":
		data, err := config.Marshal(c)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	case "client":
		if action == "list" {
			items, rev, err := a.List(ctx)
			if err != nil {
				return err
			}
			fmt.Fprintf(w, "Desired configuration revision: %d (runtime state is not tracked)\n", rev)
			for _, d := range items {
				status := "active"
				if d.Revoked {
					status = "revoked in desired configuration"
				}
				fmt.Fprintf(w, "%s\t%s\n", d.Name, status)
			}
		} else {
			if err = a.Change(ctx, action, *name); err != nil {
				return err
			}
			fmt.Fprintln(w, "Desired credentials updated. Render and deploy a new server configuration, then restart the service to apply the change.")
		}
	case "render":
		if err = a.Render(ctx, app.RenderOptions{Out: *out, Device: *name, Client: *clientTarget, URI: *uri, QR: *qr}); err != nil {
			return err
		}
		fmt.Fprintln(w, "Private bundle created. Server configuration is not applied; validate it on the server before deployment.")
		target, _ := exporter.ClientTarget(*clientTarget)
		fmt.Fprintf(w, "Client: %s (%s). Read IMPORT.txt before importing.\n", target.Label, target.Scope)
	case "check":
		if *file == "" || *binary == "" {
			return errors.New("check requires --file and --binary")
		}
		nativePath, err := filepath.Abs(*file)
		if err != nil {
			return err
		}
		work := filepath.Join(c.StateDir, "validation")
		if err = privatefs.Dir(work); err != nil {
			return err
		}
		if err = host.Check(ctx, *binary, *kind, nativePath, work); err != nil {
			return err
		}
		fmt.Fprintln(w, "Native configuration validation passed. Connectivity still requires a live test.")
	default:
		return errors.New("unknown command; run vpnctl help")
	}
	return nil
}
