package keepalive

import (
	"net"
	"runtime"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
)

var (
	keepAliveIdle     = atomic.NewInt64(0)
	keepAliveInterval = atomic.NewInt64(0)
	disableKeepAlive  = atomic.NewBool(false)
	// Negative means this inbound setting inherits its global counterpart.
	inboundKeepAliveIdle     = atomic.NewInt64(-1)
	inboundKeepAliveInterval = atomic.NewInt64(-1)
	inboundDisableKeepAlive  = atomic.NewInt64(-1)
)

func SetInboundKeepAliveIdle(t *time.Duration) {
	if t == nil {
		inboundKeepAliveIdle.Store(-1)
	} else {
		inboundKeepAliveIdle.Store(int64(*t))
	}
}

func SetInboundKeepAliveInterval(t *time.Duration) {
	if t == nil {
		inboundKeepAliveInterval.Store(-1)
	} else {
		inboundKeepAliveInterval.Store(int64(*t))
	}
}

func SetInboundDisableKeepAlive(disable *bool) {
	if disable == nil {
		inboundDisableKeepAlive.Store(-1)
	} else if *disable {
		inboundDisableKeepAlive.Store(1)
	} else {
		inboundDisableKeepAlive.Store(0)
	}
}

func InboundKeepAliveIdleOverride() *time.Duration {
	if value := inboundKeepAliveIdle.Load(); value >= 0 {
		duration := time.Duration(value)
		return &duration
	}
	return nil
}

func InboundKeepAliveIntervalOverride() *time.Duration {
	if value := inboundKeepAliveInterval.Load(); value >= 0 {
		duration := time.Duration(value)
		return &duration
	}
	return nil
}

func InboundDisableKeepAliveOverride() *bool {
	if value := inboundDisableKeepAlive.Load(); value >= 0 {
		disable := value != 0
		return &disable
	}
	return nil
}

func InboundKeepAliveIdle() time.Duration {
	if value := inboundKeepAliveIdle.Load(); value >= 0 {
		return time.Duration(value)
	}
	return KeepAliveIdle()
}

func InboundKeepAliveInterval() time.Duration {
	if value := inboundKeepAliveInterval.Load(); value >= 0 {
		return time.Duration(value)
	}
	return KeepAliveInterval()
}

func InboundDisableKeepAlive() bool {
	if runtime.GOOS == "android" {
		return true
	}
	if value := inboundDisableKeepAlive.Load(); value >= 0 {
		return value != 0
	}
	return DisableKeepAlive()
}

func SetKeepAliveIdle(t time.Duration) {
	keepAliveIdle.Store(int64(t))
}

func SetKeepAliveInterval(t time.Duration) {
	keepAliveInterval.Store(int64(t))
}

func KeepAliveIdle() time.Duration {
	return time.Duration(keepAliveIdle.Load())
}

func KeepAliveInterval() time.Duration {
	return time.Duration(keepAliveInterval.Load())
}

func SetDisableKeepAlive(disable bool) {
	if runtime.GOOS == "android" {
		setDisableKeepAlive(true)
	} else {
		setDisableKeepAlive(disable)
	}
}

func setDisableKeepAlive(disable bool) {
	disableKeepAlive.Store(disable)
}

func DisableKeepAlive() bool {
	return disableKeepAlive.Load()
}

func SetNetDialer(dialer *net.Dialer) {
	setNetDialer(dialer)
}

func SetNetListenConfig(lc *net.ListenConfig) {
	setNetListenConfig(lc)
}

func TCPKeepAlive(c net.Conn) {
	if tcp, ok := c.(TCPConn); ok && tcp != nil {
		tcpKeepAlive(tcp)
	}
}

func InboundTCPKeepAlive(c net.Conn) {
	if tcp, ok := c.(TCPConn); ok && tcp != nil {
		inboundTCPKeepAlive(tcp)
	}
}
