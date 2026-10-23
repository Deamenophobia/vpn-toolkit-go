// These tests launch isolated loopback proxies. They never enable TUN or alter routes.
package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Deamenophobia/vpn-toolkit-go/internal/app"
	"github.com/Deamenophobia/vpn-toolkit-go/internal/config"
	exporter "github.com/Deamenophobia/vpn-toolkit-go/internal/export"
	"github.com/Deamenophobia/vpn-toolkit-go/internal/host"
	"github.com/Deamenophobia/vpn-toolkit-go/internal/state"
	"go.yaml.in/yaml/v3"
)

func port(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}
func write(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}
func certificate(t *testing.T, dir string) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Integration CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "vpn.test"},
		DNSNames: []string{"vpn.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "ca.pem"), caPEM)
	write(t, filepath.Join(dir, "cert.pem"), append(leafPEM, caPEM...))
	write(t, filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}
func start(t *testing.T, exe string, args []string, listenPort int) func() {
	t.Helper()
	cmd := exec.Command(exe, args...)
	log, err := os.CreateTemp(t.TempDir(), "engine-*.log")
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() { once.Do(func() { cmd.Process.Kill(); cmd.Wait(); log.Close() }) }
	t.Cleanup(func() {
		if t.Failed() {
			data, _ := os.ReadFile(log.Name())
			for _, line := range strings.Split(string(data), "\n") {
				if strings.Contains(line, "level=warning") || strings.Contains(line, "level=error") || strings.Contains(line, "ERROR") || strings.Contains(line, "FATAL") {
					t.Log(line)
				}
			}
		}
	})
	t.Cleanup(stop)
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(listenPort)), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return stop
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("engine did not listen on the isolated test port")
	return stop
}
func fetch(proxyPort int, target string) (string, error) {
	u, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(proxyPort))
	tr := &http.Transport{Proxy: http.ProxyURL(u), DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 4 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("proxy returned HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

// Mihomo opens listeners before ApplyConfig reaches OnRunning. Probe a real
// request instead of equating an open TCP port with an operational router.
func awaitFetch(t *testing.T, proxyPort int, target, expected string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	var err error
	for time.Now().Before(deadline) {
		var got string
		got, err = fetch(proxyPort, target)
		if err == nil && got == expected {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("engine did not become operational: %v", err)
}
func udp(t *testing.T, proxyPort int) {
	t.Helper()
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		b := make([]byte, 2048)
		n, a, e := echo.ReadFromUDP(b)
		if e == nil {
			echo.WriteToUDP(b[:n], a)
		}
	}()
	control, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort)), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	control.SetDeadline(time.Now().Add(4 * time.Second))
	control.Write([]byte{5, 1, 0})
	reply := make([]byte, 2)
	if _, err = io.ReadFull(control, reply); err != nil || !bytes.Equal(reply, []byte{5, 0}) {
		t.Fatal("SOCKS authentication negotiation failed")
	}
	control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	header := make([]byte, 4)
	if _, err = io.ReadFull(control, header); err != nil || header[1] != 0 {
		t.Fatal("UDP association failed")
	}
	size := 4
	if header[3] == 4 {
		size = 16
	} else if header[3] != 1 {
		t.Fatal("unexpected SOCKS bind address type")
	}
	address := make([]byte, size+2)
	if _, err = io.ReadFull(control, address); err != nil {
		t.Fatal(err)
	}
	bindPort := int(binary.BigEndian.Uint16(address[size:]))
	socket, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: bindPort})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	socket.SetDeadline(time.Now().Add(4 * time.Second))
	ep := echo.LocalAddr().(*net.UDPAddr).Port
	frame := []byte{0, 0, 0, 1, 127, 0, 0, 1, byte(ep >> 8), byte(ep)}
	frame = append(frame, []byte("udp-over-encrypted-transport")...)
	if _, err = socket.Write(frame); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2048)
	n, err := socket.Read(response)
	if err != nil || !bytes.HasSuffix(response[:n], []byte("udp-over-encrypted-transport")) {
		t.Fatal("UDP payload did not return through the proxy")
	}
}

func TestRealEngines(t *testing.T) {
	serverBin, clientBin := os.Getenv("VPN_TEST_SING_BOX"), os.Getenv("VPN_TEST_MIHOMO")
	if serverBin == "" || clientBin == "" {
		t.Skip("set VPN_TEST_SING_BOX and VPN_TEST_MIHOMO for native integration tests")
	}
	root := t.TempDir()
	certificate(t, root)
	c := config.Defaults()
	c.StateDir = filepath.Join(root, "private")
	c.Server.Address = "127.0.0.1"
	c.Server.Listen = "127.0.0.1"
	c.Server.Port = port(t)
	c.TLS.ServerName = "vpn.test"
	c.TLS.Certificate = filepath.Join(root, "cert.pem")
	c.TLS.Key = filepath.Join(root, "key.pem")
	c.TLS.CAFile = filepath.Join(root, "ca.pem")
	c.Client.Mode = "proxy"
	c.Client.MixedPort = port(t)
	c.Client.DNSListenPort = port(t)
	a := app.New(c)
	ctx := context.Background()
	if err := a.Change(ctx, "add", "device"); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(root, "bundle")
	if err := a.Render(ctx, app.RenderOptions{Out: bundle}); err != nil {
		t.Fatal(err)
	}
	serverPath := filepath.Join(bundle, "server.json")
	clientPath := filepath.Join(bundle, "device.mihomo.yaml")
	if err := host.Check(ctx, serverBin, "server", serverPath, root); err != nil {
		t.Fatal(err)
	}
	if err := host.Check(ctx, clientBin, "client", clientPath, root); err != nil {
		t.Fatal(err)
	}
	stopServer := start(t, serverBin, []string{"run", "-c", serverPath}, c.Server.Port)
	marker := "unique-private-application-payload-426731"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, marker) }))
	defer target.Close()
	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "engine-ready") }))
	defer health.Close()

	// Capture only the encrypted link between the client engine and server engine.
	relay, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	var wire bytes.Buffer
	var mu sync.Mutex
	go func() {
		for {
			down, err := relay.Accept()
			if err != nil {
				return
			}
			go func() {
				defer down.Close()
				up, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(c.Server.Port)))
				if err != nil {
					return
				}
				defer up.Close()
				pipe := func(dst, src net.Conn) {
					defer dst.Close()
					defer src.Close()
					b := make([]byte, 32768)
					for {
						n, e := src.Read(b)
						if n > 0 {
							mu.Lock()
							wire.Write(b[:n])
							mu.Unlock()
							if _, e = dst.Write(b[:n]); e != nil {
								return
							}
						}
						if e != nil {
							return
						}
					}
				}
				go pipe(down, up)
				pipe(up, down)
			}()
		}
	}()
	profile, _ := os.ReadFile(clientPath)
	var raw map[string]any
	if err = yaml.Unmarshal(profile, &raw); err != nil {
		t.Fatal(err)
	}
	proxy := raw["proxies"].([]any)[0].(map[string]any)
	proxy["port"] = relay.Addr().(*net.TCPAddr).Port
	// No DNS listener is needed to exercise literal IP targets. The generated
	// DNS/TUN configuration was already validated by the real client parser.
	raw["dns"] = map[string]any{"enable": false}
	_, healthPort, _ := net.SplitHostPort(health.Listener.Addr().String())
	// A test-only direct health endpoint lets negative authentication cases
	// prove the router is running before checking that the VPN path is rejected.
	raw["rules"] = append([]any{"DST-PORT," + healthPort + ",DIRECT"}, raw["rules"].([]any)...)
	profile, err = yaml.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	testClient := filepath.Join(root, "test-client.yaml")
	write(t, testClient, profile)
	stopClient := start(t, clientBin, []string{"-d", root, "-f", testClient}, c.Client.MixedPort)
	awaitFetch(t, c.Client.MixedPort, health.URL, "engine-ready")
	got, err := fetch(c.Client.MixedPort, target.URL)
	if err != nil || got != marker {
		t.Fatal("generated profiles did not carry authenticated TCP traffic")
	}
	udp(t, c.Client.MixedPort)
	mu.Lock()
	captured := append([]byte(nil), wire.Bytes()...)
	mu.Unlock()
	if len(captured) == 0 || bytes.Contains(captured, []byte(marker)) || bytes.Contains(captured, []byte("udp-over-encrypted-transport")) {
		t.Fatal("application payload was exposed on the transport capture")
	}
	stopClient()

	for _, bad := range []string{"password", "server-name", "ca"} {
		t.Run("reject-"+bad, func(t *testing.T) {
			var m map[string]any
			yaml.Unmarshal(profile, &m)
			p := m["proxies"].([]any)[0].(map[string]any)
			switch bad {
			case "password":
				p["password"] = "incorrect-credential"
			case "server-name":
				p["sni"] = "wrong.test"
			case "ca":
				p["fingerprint"] = strings.Repeat("00", 32)
			}
			b, _ := yaml.Marshal(m)
			write(t, testClient, b)
			stop := start(t, clientBin, []string{"-d", root, "-f", testClient}, c.Client.MixedPort)
			defer stop()
			awaitFetch(t, c.Client.MixedPort, health.URL, "engine-ready")
			got, _ := fetch(c.Client.MixedPort, target.URL)
			if got == marker {
				t.Fatal("invalid credentials or identity accepted")
			}
		})
	}
	write(t, testClient, profile)
	stopClient = start(t, clientBin, []string{"-d", root, "-f", testClient}, c.Client.MixedPort)
	awaitFetch(t, c.Client.MixedPort, health.URL, "engine-ready")
	if err = a.Change(ctx, "rotate", "device"); err != nil {
		t.Fatal(err)
	}
	rotated := filepath.Join(root, "rotated")
	if err = a.Render(ctx, app.RenderOptions{Out: rotated}); err != nil {
		t.Fatal(err)
	}
	stopServer()
	stopServer = start(t, serverBin, []string{"run", "-c", filepath.Join(rotated, "server.json")}, c.Server.Port)
	if got, _ = fetch(c.Client.MixedPort, target.URL); got == marker {
		t.Fatal("old credential survived restart")
	}
	stopClient()
	// Keep the new client on its generated direct loopback endpoint.
	stopClient = start(t, clientBin, []string{"-d", root, "-f", filepath.Join(rotated, "device.mihomo.yaml")}, c.Client.MixedPort)
	awaitFetch(t, c.Client.MixedPort, target.URL, marker)
	if got, err = fetch(c.Client.MixedPort, target.URL); err != nil || got != marker {
		t.Fatalf("rotated credential did not work: %v", err)
	}
	if err = a.Change(ctx, "revoke", "device"); err != nil {
		t.Fatal(err)
	}
	revoked := filepath.Join(root, "revoked")
	if err = a.Render(ctx, app.RenderOptions{Out: revoked}); err != nil {
		t.Fatal(err)
	}
	if err = host.Check(ctx, serverBin, "server", filepath.Join(revoked, "server.json"), root); err != nil {
		t.Fatal("empty-user config cannot revoke last device:", err)
	}
	stopServer()
	stopServer = start(t, serverBin, []string{"run", "-c", filepath.Join(revoked, "server.json")}, c.Server.Port)
	if got, _ = fetch(c.Client.MixedPort, target.URL); got == marker {
		t.Fatal("revoked credential survived restart")
	}
	stopClient()
	stopServer()

	// Generic URIs deliberately cannot represent the private trust configuration.
	var password string
	(state.Store{Dir: c.StateDir}).With(ctx, func(s *state.State) error { password = s.Devices["device"].Password; return nil }, false)
	if _, err = exporter.URI(c, "device", password); err == nil {
		t.Fatal("custom CA trust was silently discarded from URI")
	}
}

func TestSingBoxOutboundSchema(t *testing.T) {
	binary := os.Getenv("VPN_TEST_SING_BOX")
	if binary == "" {
		t.Skip("set VPN_TEST_SING_BOX for native schema validation")
	}
	c := config.Defaults()
	c.TLS.ServerName = "vpn.example.com"
	for _, address := range []string{"127.0.0.1", "vpn.example.com", "2001:db8::7"} {
		c.Server.Address = address
		name, data, err := exporter.ClientProfile(c, "device", "native-schema-test-password", "sing-box")
		if err != nil {
			t.Fatal(err)
		}
		root := t.TempDir()
		path := filepath.Join(root, name)
		write(t, path, data)
		if err = host.Check(context.Background(), binary, "sing-box-client", path, root); err != nil {
			t.Fatal(err)
		}
	}
}
