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

func TestInboundKeepAliveOverridesDoNotChangeOutbound(t *testing.T) {
	previousIdle := KeepAliveIdle()
	previousInterval := KeepAliveInterval()
	previousDisabled := DisableKeepAlive()
	previousInboundIdle := InboundKeepAliveIdleOverride()
	previousInboundInterval := InboundKeepAliveIntervalOverride()
	previousInboundDisabled := InboundDisableKeepAliveOverride()
	t.Cleanup(func() {
		SetKeepAliveIdle(previousIdle)
		SetKeepAliveInterval(previousInterval)
		SetDisableKeepAlive(previousDisabled)
		SetInboundKeepAliveIdle(previousInboundIdle)
		SetInboundKeepAliveInterval(previousInboundInterval)
		SetInboundDisableKeepAlive(previousInboundDisabled)
	})

	SetKeepAliveIdle(120 * time.Second)
	SetKeepAliveInterval(120 * time.Second)
	SetDisableKeepAlive(false)
	SetInboundKeepAliveIdle(nil)
	SetInboundKeepAliveInterval(nil)
	SetInboundDisableKeepAlive(nil)
	value := 3600 * time.Second
	SetInboundKeepAliveIdle(&value)
	SetInboundKeepAliveInterval(&value)

	inbound := &testTCPConn{}
	InboundTCPKeepAlive(inbound)
	if !inbound.config.Enable || inbound.config.Idle != value || inbound.config.Interval != value {
		t.Fatalf("inbound override not applied: %+v", inbound.config)
	}
	outbound := &net.Dialer{}
	SetNetDialer(outbound)
	if outbound.KeepAliveConfig.Idle != 120*time.Second || outbound.KeepAliveConfig.Interval != 120*time.Second {
		t.Fatalf("outbound settings changed: %+v", outbound.KeepAliveConfig)
	}
	listener := &net.ListenConfig{}
	SetNetListenConfig(listener)
	if listener.KeepAliveConfig.Idle != value || listener.KeepAliveConfig.Interval != value {
		t.Fatalf("inbound listener override not applied: %+v", listener.KeepAliveConfig)
	}

	// New inbound connections observe reloads; outbound connections keep their own settings.
	newValue := 600 * time.Second
	SetInboundKeepAliveIdle(&newValue)
	second := &testTCPConn{}
	InboundTCPKeepAlive(second)
	if second.config.Idle != newValue || second.config.Interval != value || inbound.config.Idle != value {
		t.Fatalf("inbound reload changed wrong connections: old=%+v new=%+v", inbound.config, second.config)
	}
	if outbound.KeepAliveConfig.Idle != 120*time.Second {
		t.Fatalf("outbound dialer was changed: %+v", outbound.KeepAliveConfig)
	}

	SetInboundKeepAliveIdle(nil)
	SetInboundKeepAliveInterval(nil)
	SetKeepAliveIdle(240 * time.Second)
	third := &testTCPConn{}
	InboundTCPKeepAlive(third)
	if third.config.Idle != 240*time.Second || third.config.Interval != 120*time.Second {
		t.Fatalf("unset overrides did not inherit global settings: %+v", third.config)
	}

	disable := true
	SetInboundDisableKeepAlive(&disable)
	fourth := &testTCPConn{}
	InboundTCPKeepAlive(fourth)
	if !fourth.disabled || fourth.config.Enable {
		t.Fatalf("inbound disable override was not applied: %+v", fourth)
	}
	SetNetDialer(outbound)
	if !outbound.KeepAliveConfig.Enable {
		t.Fatal("inbound disable override disabled outbound keepalive")
	}
	disable = false
	SetInboundDisableKeepAlive(&disable)
	SetDisableKeepAlive(true)
	fifth := &testTCPConn{}
	InboundTCPKeepAlive(fifth)
	if !fifth.config.Enable || fifth.disabled {
		t.Fatalf("explicit inbound enable did not override global disable: %+v", fifth)
	}
	SetNetDialer(outbound)
	if outbound.KeepAliveConfig.Enable {
		t.Fatal("global disable did not apply to outbound dialer")
	}
}
