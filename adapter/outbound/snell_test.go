package outbound

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"maps"
	"math/big"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/snell"

	"github.com/metacubex/tls"
)

func TestSnellECHTLSUsesRawTLSWithoutPath(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}

	adapter, err := NewSnell(SnellOption{
		Name:    "snell",
		Server:  "origin.example.com",
		Port:    443,
		Psk:     "password",
		Version: 4,
		ObfsOpts: map[string]any{
			"mode":       "ech-tls",
			"ech-config": echConfig,
		},
	})
	if err != nil {
		t.Fatalf("NewSnell() error = %v", err)
	}
	defer adapter.Close()

	if adapter.echTLS == nil || adapter.echTLS.ECH == nil {
		t.Fatal("ECH TLS config was not initialized")
	}
	if adapter.echTLS.ClientSessionCache == nil || adapter.echTLS.UClientSessionCache == nil {
		t.Fatal("ECH TLS session caches were not initialized")
	}
	if len(adapter.echTLS.NextProtos) != 1 || adapter.echTLS.NextProtos[0] != snellECHTLSALPN {
		t.Fatalf("NextProtos = %q, want [%q]", adapter.echTLS.NextProtos, snellECHTLSALPN)
	}
}

func TestSnellECHTLSResolvesClientFingerprint(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		obfs string
		top  string
		want string
	}{
		{name: "obfs none", obfs: "none", want: defaultSnellClientFingerprint},
		{name: "proxy none", top: "NONE", want: defaultSnellClientFingerprint},
		{name: "explicit", obfs: "firefox", want: "firefox"},
		{name: "case", top: "FireFox120", want: "firefox120"},
		{name: "without ech", obfs: "safari", want: defaultSnellClientFingerprint},
		{name: "unknown", obfs: "chrome131", want: defaultSnellClientFingerprint},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obfs := map[string]any{"mode": "ech-tls", "ech-config": echConfig}
			if tc.obfs != "" {
				obfs["client-fingerprint"] = tc.obfs
			}
			adapter, err := NewSnell(SnellOption{
				Name: "snell", Server: "origin.example.com", Port: 443, Psk: "password", Version: 4,
				ClientFingerprint: tc.top, ObfsOpts: obfs,
			})
			if err != nil {
				t.Fatalf("NewSnell() error = %v", err)
			}
			defer adapter.Close()
			if got := adapter.echTLS.ClientFingerprint; got != tc.want {
				t.Fatalf("ClientFingerprint = %q, want %q", got, tc.want)
			}
		})
	}
}

// clientBytesRecorder keeps what a server reads from its client.
type clientBytesRecorder struct {
	net.Conn
	read []byte
}

func (c *clientBytesRecorder) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.read = append(c.read, b[:n]...)
	return n, err
}

// snellECHTestServer returns a TLS 1.3 server config with fresh ECH keys and a
// certificate for origin.example.com, and the ech-config and ca-file of a client.
func snellECHTestServer(t *testing.T) (config *tls.Config, echConfig, caPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"origin.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	echConfig, echKeyPEM, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(echKeyPEM))
	echKeys, err := ech.UnmarshalECHKeys(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	config = &tls.Config{
		NextProtos: []string{snellECHTLSALPN}, MinVersion: tls.VersionTLS13,
		Certificates:             []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		EncryptedClientHelloKeys: echKeys,
	}
	return config, echConfig, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestSnellECHTLSFingerprintsKeepALPNPrivate(t *testing.T) {
	serverConfig, echConfig, caPEM := snellECHTestServer(t)

	// Every name in component/tls's fingerprint table, then none, a wrong case and an unknown name.
	for _, fingerprint := range []string{
		"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random",
		"chrome120", "firefox120", "safari16", "chrome_psk", "chrome_psk_shuffle",
		"chrome_padding_psk_shuffle", "chrome_pq", "chrome_pq_psk", "randomized",
		"none", "Chrome", "chrome131",
	} {
		t.Run(fingerprint, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			hello := make(chan []byte, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					hello <- nil
					return
				}
				defer conn.Close()
				recorder := &clientBytesRecorder{Conn: conn}
				server := tls.Server(recorder, serverConfig)
				_ = server.SetDeadline(time.Now().Add(5 * time.Second))
				_ = server.Handshake()
				hello <- bytes.Clone(recorder.read)
				_, _ = io.Copy(io.Discard, server)
			}()

			adapter, err := NewSnell(SnellOption{
				Name: "snell", Server: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, Psk: "password", Version: 4,
				ObfsOpts: map[string]any{
					"mode": "ech-tls", "ech-config": echConfig, "sni": "origin.example.com",
					"ca-file": caPEM, "client-fingerprint": fingerprint,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer adapter.Close()
			used := adapter.echTLS.ClientFingerprint
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := adapter.dialSnellTransport(ctx)
			if err != nil {
				t.Fatalf("handshake with %s: %v", used, err)
			}
			defer conn.Close()
			if state := tlsC.GetTLSConnectionState(conn); !state.ECHAccepted || state.NegotiatedProtocol != snellECHTLSALPN {
				t.Fatalf("%s: ECH accepted %v, ALPN %q", used, state.ECHAccepted, state.NegotiatedProtocol)
			}
			select {
			case raw := <-hello:
				for _, private := range []string{snellECHTLSALPN, "origin.example.com"} {
					if bytes.Contains(raw, []byte(private)) {
						t.Fatalf("%s sends %s in the clear", used, private)
					}
				}
			case <-time.After(5 * time.Second):
				t.Fatal("server handshake did not finish")
			}
		})
	}
}

func TestSnellECHTLSRejectsSkippedCertificateVerification(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewSnell(SnellOption{
		Name: "snell", Server: "origin.example.com", Port: 443, Psk: "password", Version: 4,
		ObfsOpts: map[string]any{
			"mode": "ech-tls", "ech-config": echConfig, "skip-cert-verify": true,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "requires certificate verification") {
		t.Fatalf("NewSnell() error = %v", err)
	}
}

// Cached subscriptions keep identity-version, legacy-fallback and the protocol
// alias of the retired h2 path. They still load, and dial only the version's
// ALPN with the identity bound to the TLS exporter.
func TestSnellECHTLSIgnoresRetiredOptions(t *testing.T) {
	serverConfig, echConfig, caPEM := snellECHTestServer(t)
	// The retired path's server negotiates h2 for any client that offers it.
	serverConfig.NextProtos = []string{"h2", snellECHTLSALPN, snellECHTLSV6ALPN}
	psk := []byte("password")
	for _, version := range []int{snell.Version4, snell.Version6} {
		alpn, magic := snellECHTLSALPN, "DLSNID02"
		if version == snell.Version6 {
			alpn, magic = snellECHTLSV6ALPN, "DLSNID06"
		}
		for _, cached := range []struct {
			name string
			obfs map[string]any
		}{
			{"subscription", map[string]any{"alpn": alpn, "identity-version": 2, "legacy-fallback": false}},
			{"hand-edited", map[string]any{"protocol": "oix-snell/1", "identity-version": 1, "legacy-fallback": true}},
		} {
			t.Run(strconv.Itoa(version)+"/"+cached.name, func(t *testing.T) {
				newSnell := func(port int, transport string) *Snell {
					t.Helper()
					obfs := map[string]any{
						"mode": "ech-tls", "ech-config": echConfig, "sni": "origin.example.com",
						"ca-file": caPEM, "transport": transport,
					}
					maps.Copy(obfs, cached.obfs)
					adapter, err := NewSnell(SnellOption{
						Name: "snell", Server: "127.0.0.1", Port: port, Psk: string(psk), Version: version,
						Identity: true, IdentityConfigured: true, ObfsOpts: obfs,
					})
					if err != nil {
						t.Fatalf("%s: %v", transport, err)
					}
					t.Cleanup(func() { _ = adapter.Close() })
					if got := adapter.echTLS.NextProtos; !slices.Equal(got, []string{alpn}) {
						t.Fatalf("%s NextProtos = %q, want [%q]", transport, got, alpn)
					}
					return adapter
				}
				newSnell(443, "h3")
				newSnell(443, "auto")

				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				type handshake struct {
					offered         []string
					alpn            string
					exporter, first []byte
					err             error
				}
				result := make(chan handshake, 1)
				go func() {
					var h handshake
					defer func() { result <- h }()
					conn, err := listener.Accept()
					if h.err = err; err != nil {
						return
					}
					defer conn.Close()
					config := serverConfig.Clone()
					config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
						h.offered = hello.SupportedProtos
						return nil, nil
					}
					server := tls.Server(conn, config)
					_ = server.SetDeadline(time.Now().Add(5 * time.Second))
					h.first = make([]byte, 56)
					if _, h.err = io.ReadFull(server, h.first); h.err != nil {
						return
					}
					state := server.ConnectionState()
					h.alpn = state.NegotiatedProtocol
					h.exporter, h.err = state.ExportKeyingMaterial(snell.IdentityExporterLabel, []byte{}, snell.IdentityExporterLength)
				}()
				adapter := newSnell(listener.Addr().(*net.TCPAddr).Port, "tcp")
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				conn, err := adapter.dialSnell(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				if err = snell.WriteHeaderWithReuse(conn, "example.com", 443, version, true); err != nil {
					t.Fatal(err)
				}
				h := <-result
				if h.err != nil {
					t.Fatal(h.err)
				}
				if !slices.Equal(h.offered, []string{alpn}) || h.alpn != alpn {
					t.Fatalf("offered ALPN %q, negotiated %q, want only %q", h.offered, h.alpn, alpn)
				}
				if string(h.first[16:24]) != magic || !bytes.Equal(h.first[24:40], snell.IdentityV2HeaderFromPSK(psk)) {
					t.Fatalf("identity header %q %x", h.first[16:24], h.first[24:40])
				}
				if version == snell.Version4 {
					tag, err := snell.IdentityV2AuthTag(psk, h.exporter, h.first[:16])
					if err != nil || !bytes.Equal(h.first[40:], tag) {
						t.Fatalf("identity is not bound to the TLS exporter: %v", err)
					}
				}
			})
		}
	}
}

// identity only applies to ech-tls: other modes send plain records and skip the
// warmup that a standard Snell server answers by closing the connection.
func TestSnellIgnoresIdentityWithoutECHTLS(t *testing.T) {
	raw, peer := net.Pipe()
	t.Cleanup(func() { _ = raw.Close(); _ = peer.Close() })
	adapter, err := NewSnell(SnellOption{
		BasicOption: BasicOption{DialerForAPI: cleanupTestDialer{conn: raw}},
		Name:        "snell", Server: "127.0.0.1", Port: 443, Psk: "password",
		Version: snell.Version4, Identity: true, IdentityConfigured: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = adapter.Close() })
	go func() {
		conn, err := adapter.DialContext(context.Background(), &C.Metadata{NetWork: C.TCP, Host: "example.com", DstPort: 80})
		if err == nil {
			_ = conn.Close()
		}
	}()
	_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
	request := make([]byte, 3)
	if _, err := io.ReadFull(snell.ServerStreamConn(peer, []byte("password"), snell.Version4), request); err != nil {
		t.Fatalf("plain Snell request: %v", err)
	}
	if request[0] != snell.Version || request[1] != snell.CommandConnectV2 {
		t.Fatalf("first request = %x, want a reusable connect without warmup", request)
	}

	// shadow-tls used to force the identity as well, and still defaults to v4.
	shadow, err := NewSnell(SnellOption{
		Name: "snell", Server: "127.0.0.1", Port: 443, Psk: "password", IdentityConfigured: true,
		ShadowTLSPassword: "password", ShadowTLSSNI: "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer shadow.Close()
	if shadow.identity || shadow.version != snell.Version4 {
		t.Fatalf("shadow-tls identity = %v, version = %d", shadow.identity, shadow.version)
	}
}

func TestSnellRejectsAnyTLSObfs(t *testing.T) {
	_, err := NewSnell(SnellOption{
		Name:   "snell",
		Server: "127.0.0.1",
		Port:   443,
		Psk:    "password",
		ObfsOpts: map[string]any{
			"mode":     "anytls",
			"password": "outer-password",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "obfs mode error: anytls") {
		t.Fatalf("NewSnell() error = %v, want unsupported anytls obfs", err)
	}
}

func TestSnellRejectsDisabledIdentityForECHTLS(t *testing.T) {
	_, err := NewSnell(SnellOption{
		Name:               "snell",
		Server:             "127.0.0.1",
		Port:               443,
		Psk:                "password",
		Version:            4,
		IdentityConfigured: true,
		ObfsOpts: map[string]any{
			"mode":       "ech-tls",
			"path":       "/snell",
			"ech-config": "invalid",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "identity cannot be disabled") {
		t.Fatalf("NewSnell() error = %v, want disabled identity error", err)
	}
}

func TestSnellClampsPreconnect(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		obfs map[string]any
		want int
	}{
		{"tls above", map[string]any{"mode": "tls", "preconnect": 200}, 4},
		{"plain below", map[string]any{"preconnect": -1}, 0},
		{"ech-tls above", map[string]any{"mode": "ech-tls", "ech-config": echConfig, "preconnect": 5}, 4},
		{"ech-tls below", map[string]any{"mode": "ech-tls", "ech-config": echConfig, "preconnect": -2}, 0},
		{"ech-tls within", map[string]any{"mode": "ech-tls", "ech-config": echConfig, "preconnect": 3}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adapter, err := NewSnell(SnellOption{
				BasicOption: BasicOption{DialerForAPI: &countingSnellDialer{gate: make(chan struct{})}},
				Name:        "snell", Server: "127.0.0.1", Port: 443, Psk: "password", Version: 4, ObfsOpts: tc.obfs,
			})
			if err != nil {
				t.Fatalf("NewSnell() error = %v", err)
			}
			defer adapter.Close()
			if got := adapter.obfsOption.Preconnect; got != tc.want {
				t.Fatalf("preconnect = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestSnellPreconnectWarmsAtMostTheSupportedCount(t *testing.T) {
	dialer := &countingSnellDialer{newConn: discardingPipe}
	adapter, err := NewSnell(SnellOption{
		BasicOption: BasicOption{DialerForAPI: dialer},
		Name:        "snell", Server: "127.0.0.1", Port: 443, Psk: "password", Version: 4,
		ObfsOpts: map[string]any{"mode": "tls", "preconnect": 200},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	for deadline := time.Now().Add(5 * time.Second); dialer.dials.Load() < 4 && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if dials := dialer.dials.Load(); dials != 4 {
		t.Fatalf("preconnect 200 dialed %d connections, want 4", dials)
	}
}
