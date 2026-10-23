// Package host provides opt-in checks and a service template, not remote access.
package host

import (
	"context"
	"errors"
	"github.com/Deamenophobia/vpn-toolkit-go/internal/engine"
	"os/exec"
	"strings"
	"time"
)

const Service = `[Unit]
Description=Personal encrypted proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=vpn-toolkit
Group=vpn-toolkit
ExecStartPre=/usr/local/bin/sing-box check -c /etc/vpn-toolkit/server.json
ExecStart=/usr/local/bin/sing-box run -c /etc/vpn-toolkit/server.json
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
`

func Check(ctx context.Context, binary, kind, path, workDir string) error {
	var versionArgs, args []string
	expected := ""
	switch kind {
	case "server", "sing-box-client":
		versionArgs = []string{"version"}
		expected = engine.SingBoxVersion
		args = []string{"check", "-c", path}
	case "client":
		versionArgs = []string{"-v"}
		expected = engine.MihomoVersion
		args = []string{"-t", "-d", workDir, "-f", path}
	default:
		return errors.New("check kind must be server, client (Mihomo), or sing-box-client")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, binary, versionArgs...).CombinedOutput()
	if err != nil {
		return errors.New("cannot execute engine version check")
	}
	found := false
	for _, word := range strings.Fields(string(b)) {
		if strings.TrimPrefix(word, "v") == expected {
			found = true
		}
	}
	if !found {
		return errors.New("engine version differs from the tested pair; see docs/COMPATIBILITY.md")
	}
	// Native diagnostics may contain credential-bearing configuration. Do not echo them.
	if err = exec.CommandContext(ctx, binary, args...).Run(); err != nil {
		return errors.New("native configuration validation failed; check fields and certificate paths on the target machine")
	}
	return nil
}
