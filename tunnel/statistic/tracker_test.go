package statistic

import (
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestTrackerMetadataCopiesMetadata(t *testing.T) {
	original := &C.Metadata{
		Host:  "example.com",
		DstIP: netip.MustParseAddr("192.0.2.1"),
	}

	processed := trackerMetadata(original, "198.51.100.1:443")

	if original.Host != "example.com" || original.DstIP.String() != "192.0.2.1" || original.RemoteDst != "" {
		t.Fatalf("original metadata was modified: %+v", original)
	}
	if processed == original || processed.Host != "example.com" || processed.DstIP.String() != "192.0.2.1" {
		t.Fatalf("tracker metadata was not copied independently: %+v", processed)
	}
	if processed.RemoteDst != "198.51.100.1:443" {
		t.Fatalf("tracker remote destination = %q", processed.RemoteDst)
	}
}
