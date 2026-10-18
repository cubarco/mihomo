package config

import "testing"

func TestParseTunKeepsCongestionController(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte("tun:\n  stack: mips\n  congestion-controller: bbr\n"))
	if err != nil {
		t.Fatal(err)
	}
	general := &General{}
	if err := parseTun(raw.Tun, &DNS{}, general); err != nil {
		t.Fatal(err)
	}
	if got := general.Tun.CongestionController; got != "bbr" {
		t.Fatalf("congestion controller = %q, want bbr", got)
	}
	// ReCreateTun keeps the running TUN while the options are Equal.
	changed := general.Tun
	changed.CongestionController = "cubic"
	if general.Tun.Equal(changed) {
		t.Fatal("a changed congestion controller left the TUN options equal")
	}
}
