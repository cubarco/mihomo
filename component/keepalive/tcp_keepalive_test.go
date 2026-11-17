package keepalive

import (
	"net"
	"testing"
	"time"
)

type testTCPConn struct {
	net.Conn
	config   net.KeepAliveConfig
	disabled bool
}

func (c *testTCPConn) SetKeepAlive(enabled bool) error {
	c.disabled = !enabled
	return nil
}

func (c *testTCPConn) SetKeepAliveConfig(config net.KeepAliveConfig) error {
	c.config = config
	return nil
}

func TestTCPKeepAliveUsesCurrentSettings(t *testing.T) {
	previousIdle := KeepAliveIdle()
	previousInterval := KeepAliveInterval()
	previousDisabled := DisableKeepAlive()
	t.Cleanup(func() {
		SetKeepAliveIdle(previousIdle)
		SetKeepAliveInterval(previousInterval)
		SetDisableKeepAlive(previousDisabled)
	})

	SetKeepAliveIdle(120 * time.Second)
	SetKeepAliveInterval(120 * time.Second)
	SetDisableKeepAlive(false)
	first := &testTCPConn{}
	TCPKeepAlive(first)
	if !first.config.Enable || first.config.Idle != 120*time.Second || first.config.Interval != 120*time.Second {
		t.Fatalf("unexpected keepalive configuration: %+v", first.config)
	}

	SetKeepAliveIdle(180 * time.Second)
	second := &testTCPConn{}
	TCPKeepAlive(second)
	if second.config.Idle != 180*time.Second || second.config.Interval != 120*time.Second {
		t.Fatalf("new connection did not use updated settings: %+v", second.config)
	}

	SetDisableKeepAlive(true)
	third := &testTCPConn{}
	TCPKeepAlive(third)
	if !third.disabled || third.config.Enable {
		t.Fatalf("keepalive was not disabled: %+v", third)
	}
}
