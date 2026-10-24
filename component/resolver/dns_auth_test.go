package resolver

import (
	"context"
	"encoding/base64"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

type dnsAuthCaptureResolver struct {
	Resolver
	host string
}

func (r *dnsAuthCaptureResolver) LookupIP(_ context.Context, host string) ([]netip.Addr, error) {
	r.host = host
	return nil, nil
}

func (r *dnsAuthCaptureResolver) LookupIPv4(_ context.Context, host string) ([]netip.Addr, error) {
	r.host = host
	return nil, nil
}

func (r *dnsAuthCaptureResolver) LookupIPv6(_ context.Context, host string) ([]netip.Addr, error) {
	r.host = host
	return nil, nil
}

func (r *dnsAuthCaptureResolver) ResolveECH(_ context.Context, host string) ([]byte, error) {
	r.host = host
	return nil, nil
}

func TestDNSAuthProxyResolverPreservesSignedLookups(t *testing.T) {
	// The test key is deterministic and unrelated to the local build key.
	t.Setenv("MIHOMO_DNS_AUTH_PRIVATE_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("MIHOMO_DNS_AUTH_DOMAINS", "auth.example")
	t.Setenv("MIHOMO_DNS_AUTH_ENABLED", "true")
	dnsAuthOnce = sync.Once{}
	dnsAuthConfig = nil
	t.Cleanup(func() {
		dnsAuthOnce = sync.Once{}
		dnsAuthConfig = nil
	})

	underlying := &dnsAuthCaptureResolver{}
	wrapped := WrapDNSAuthResolver(underlying)
	if _, ok := wrapped.(*dnsAuthResolver); !ok {
		t.Fatal("DNS-Auth did not wrap the proxy-server resolver")
	}
	ctx := context.Background()
	lookups := []struct {
		name string
		call func() error
	}{
		{"A+AAAA", func() error { _, err := wrapped.LookupIP(ctx, "Edge.Auth.Example."); return err }},
		{"A", func() error { _, err := wrapped.LookupIPv4(ctx, "Edge.Auth.Example."); return err }},
		{"AAAA", func() error { _, err := wrapped.LookupIPv6(ctx, "Edge.Auth.Example."); return err }},
		{"ECH", func() error { _, err := wrapped.ResolveECH(ctx, "Edge.Auth.Example."); return err }},
	}
	for _, lookup := range lookups {
		t.Run(lookup.name, func(t *testing.T) {
			if err := lookup.call(); err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(underlying.host, ".")
			if len(parts) != 6 || len(parts[0]) != 52 || len(parts[1]) != 52 || !strings.HasSuffix(underlying.host, ".edge.auth.example.") {
				t.Fatalf("managed hostname was not signed: labels=%d", len(parts))
			}
		})
	}
	if _, err := wrapped.LookupIPv4(ctx, "ordinary.example"); err != nil {
		t.Fatal(err)
	}
	if underlying.host != "ordinary.example" {
		t.Fatal("unmanaged hostname was changed")
	}
}
