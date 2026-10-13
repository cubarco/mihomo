package outbound

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/tls"
)

type tlsStreamProxy interface {
	StreamConnContext(context.Context, net.Conn, *C.Metadata) (net.Conn, error)
}

func TestProxyTLSSessionReuse(t *testing.T) {
	certPEM, keyPEM, pin, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"http", "socks5"} {
		for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
			t.Run(kind+"/"+tls.VersionName(version), func(t *testing.T) {
				newProxy := func(clientCert bool) (tlsStreamProxy, *tls.Config) {
					var cert, key string
					if clientCert {
						cert, key = certPEM, keyPEM
					}
					if kind == "http" {
						proxy, err := NewHttp(HttpOption{Name: "fixture", Server: "proxy.test", Port: 443, TLS: true, Fingerprint: pin, Certificate: cert, PrivateKey: key})
						if err != nil {
							t.Fatal(err)
						}
						return proxy, proxy.tlsConfig
					}
					proxy, err := NewSocks5(Socks5Option{Name: "fixture", Server: "proxy.test", Port: 443, TLS: true, Fingerprint: pin, Certificate: cert, PrivateKey: key})
					if err != nil {
						t.Fatal(err)
					}
					return proxy, proxy.tlsConfig
				}
				serverConfig := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: version, MaxVersion: version}
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				dial := func(proxy tlsStreamProxy) bool {
					done := make(chan error, 1)
					go func() {
						raw, err := listener.Accept()
						if err != nil {
							done <- err
							return
						}
						defer raw.Close()
						_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
						conn := tls.Server(raw, serverConfig)
						if kind == "http" {
							var req *http.Request
							req, err = http.ReadRequest(bufio.NewReader(conn))
							if err == nil && (req.Method != "CONNECT" || req.Host != "destination.test:443") {
								err = fmt.Errorf("unexpected CONNECT request: %v", req)
							}
							if err == nil {
								_, err = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
							}
						} else {
							var addr socks5.Addr
							var command socks5.Command
							addr, command, _, err = socks5.ServerHandshake(conn, nil)
							if err == nil && (addr.String() != "destination.test:443" || command != socks5.CmdConnect) {
								err = fmt.Errorf("unexpected SOCKS request: %v %v", addr, command)
							}
						}
						done <- err
					}()
					raw, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
					if err != nil {
						t.Fatal(err)
					}
					defer raw.Close()
					_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
					conn, err := proxy.StreamConnContext(context.Background(), raw, &C.Metadata{Host: "destination.test", DstPort: 443})
					if err != nil {
						t.Fatal(err)
					}
					if err := <-done; err != nil {
						t.Fatal(err)
					}
					return conn.(*tls.Conn).ConnectionState().DidResume
				}
				proxy, _ := newProxy(false)
				for attempt := range 3 {
					if resumed := dial(proxy); resumed != (attempt > 0) {
						t.Fatalf("connection %d: resumed=%v", attempt, resumed)
					}
				}
				replacement, _ := newProxy(false)
				if dial(replacement) {
					t.Fatal("replacement outbound inherited the old session")
				}
				_, clientCertificateConfig := newProxy(true)
				if clientCertificateConfig.ClientSessionCache != nil {
					t.Fatal("session reuse may bypass a client certificate reload")
				}
			})
		}
	}
}
