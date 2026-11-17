package config

import "testing"

func TestInboundKeepAliveOverrides(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte("keep-alive-idle: 120\nkeep-alive-interval: 120\ninbound-keep-alive-idle: 3600\ninbound-keep-alive-interval: 3600\ninbound-disable-keep-alive: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	general, err := parseGeneral(raw)
	if err != nil {
		t.Fatal(err)
	}
	if general.KeepAliveIdle != 120 || general.KeepAliveInterval != 120 || general.InboundKeepAliveIdle == nil || *general.InboundKeepAliveIdle != 3600 || general.InboundKeepAliveInterval == nil || *general.InboundKeepAliveInterval != 3600 || general.InboundDisableKeepAlive == nil || *general.InboundDisableKeepAlive {
		t.Fatalf("inbound keepalive overrides were not parsed separately: %+v", general)
	}

	general, err = parseGeneral(DefaultRawConfig())
	if err != nil {
		t.Fatal(err)
	}
	if general.InboundKeepAliveIdle != nil || general.InboundKeepAliveInterval != nil || general.InboundDisableKeepAlive != nil {
		t.Fatalf("omitted inbound keepalive settings must inherit global settings: %+v", general)
	}
}

func TestInboundKeepAliveRejectsNegativeSeconds(t *testing.T) {
	for _, input := range []string{"inbound-keep-alive-idle: -1\n", "inbound-keep-alive-interval: -1\n"} {
		raw, err := UnmarshalRawConfig([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseGeneral(raw); err == nil {
			t.Fatalf("negative inbound keepalive value was accepted: %q", input)
		}
	}
}
