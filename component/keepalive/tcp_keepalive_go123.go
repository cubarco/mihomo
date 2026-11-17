//go:build go1.23

package keepalive

import (
	"net"
	"time"
)

type TCPConn interface {
	net.Conn
	SetKeepAlive(keepalive bool) error
	SetKeepAliveConfig(config net.KeepAliveConfig) error
}

func keepAliveConfig() net.KeepAliveConfig {
	return newKeepAliveConfig(KeepAliveIdle(), KeepAliveInterval())
}

func inboundKeepAliveConfig() net.KeepAliveConfig {
	return newKeepAliveConfig(InboundKeepAliveIdle(), InboundKeepAliveInterval())
}

func newKeepAliveConfig(idle, interval time.Duration) net.KeepAliveConfig {
	config := net.KeepAliveConfig{Enable: true, Idle: idle, Interval: interval}
	if !SupportTCPKeepAliveCount() {
		// it's recommended to set both Idle and Interval to non-negative values in conjunction with a -1
		// for Count on those old Windows if you intend to customize the TCP keep-alive settings.
		config.Count = -1
	}
	return config
}

func tcpKeepAlive(tcp TCPConn) {
	if DisableKeepAlive() {
		_ = tcp.SetKeepAlive(false)
	} else {
		_ = tcp.SetKeepAliveConfig(keepAliveConfig())
	}
}

func inboundTCPKeepAlive(tcp TCPConn) {
	if InboundDisableKeepAlive() {
		_ = tcp.SetKeepAlive(false)
	} else {
		_ = tcp.SetKeepAliveConfig(inboundKeepAliveConfig())
	}
}

func setNetDialer(dialer *net.Dialer) {
	if DisableKeepAlive() {
		dialer.KeepAlive = -1 // If negative, keep-alive probes are disabled.
		dialer.KeepAliveConfig.Enable = false
	} else {
		dialer.KeepAliveConfig = keepAliveConfig()
	}
}

func setNetListenConfig(lc *net.ListenConfig) {
	if InboundDisableKeepAlive() {
		lc.KeepAlive = -1 // If negative, keep-alive probes are disabled.
		lc.KeepAliveConfig.Enable = false
	} else {
		lc.KeepAliveConfig = inboundKeepAliveConfig()
	}
}
