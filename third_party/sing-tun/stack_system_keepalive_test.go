package tun

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
)

type systemKeepAliveConn struct {
	net.Conn
}

func (c *systemKeepAliveConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

type systemKeepAliveListener struct {
	conn net.Conn
}

func (l *systemKeepAliveListener) Accept() (net.Conn, error) {
	if l.conn == nil {
		return nil, net.ErrClosed
	}
	conn := l.conn
	l.conn = nil
	return conn, nil
}

func (l *systemKeepAliveListener) Close() error   { return nil }
func (l *systemKeepAliveListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestSystemAppliesTCPKeepAliveToAcceptedConnection(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn := &systemKeepAliveConn{Conn: server}
	configured := false
	accepted := make(chan struct{})
	handler := &testHandler{tcp: func(_ context.Context, _ net.Conn, _ M.Metadata) error {
		close(accepted)
		return nil
	}}
	stack, err := NewSystem(StackOptions{
		Context:    context.Background(),
		TunOptions: Options{Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}},
		Handler:    handler,
		Logger:     logger.NOP(),
		TCPKeepAlive: func(got net.Conn) {
			if got != conn {
				t.Errorf("configured a different connection")
			}
			configured = true
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	nat := &TCPNat{portMap: map[uint16]*TCPSession{
		12345: {
			Source:      netip.MustParseAddrPort("192.0.2.1:23456"),
			Destination: netip.MustParseAddrPort("198.51.100.1:443"),
			LastActive:  time.Now(),
		},
	}}
	stack.(*System).acceptLoop(&systemKeepAliveListener{conn: conn}, nat)
	if !configured {
		t.Fatal("TCP keepalive hook was not called")
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("connection was not forwarded")
	}
}
