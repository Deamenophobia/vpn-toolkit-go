package engine

import (
	"encoding/json"
	"github.com/Deamenophobia/vpn-toolkit-go/internal/config"
	"github.com/Deamenophobia/vpn-toolkit-go/internal/state"
	"sort"
)

const SingBoxVersion = "1.14.3"
const MihomoVersion = "1.19.33"

type Adapter interface {
	Render(config.Config, state.State) ([]byte, error)
}
type AnyTLS struct{}

func (AnyTLS) Render(c config.Config, s state.State) ([]byte, error) {
	names := make([]string, 0, len(s.Devices))
	for n, d := range s.Devices {
		if !d.Revoked {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	users := make([]map[string]string, 0, len(names))
	for _, n := range names {
		users = append(users, map[string]string{"name": n, "password": s.Devices[n].Password})
	}
	out := map[string]any{
		"log":   map[string]any{"level": c.Server.LogLevel},
		"dns":   map[string]any{"servers": []any{map[string]any{"type": "udp", "tag": "resolver", "server": c.Server.DNS}}},
		"route": map[string]any{"final": "direct", "default_domain_resolver": "resolver"},
		"inbounds": []any{map[string]any{
			"type": "anytls", "tag": "vpn-in", "listen": c.Server.Listen, "listen_port": c.Server.Port, "users": users,
			"tls": map[string]any{"enabled": true, "min_version": "1.3", "certificate_path": c.TLS.Certificate, "key_path": c.TLS.Key},
		}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
	}
	b, err := json.MarshalIndent(out, "", "  ")
	return append(b, '\n'), err
}
