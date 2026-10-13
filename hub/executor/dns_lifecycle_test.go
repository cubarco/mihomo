package executor

import (
	"context"
	"errors"
	"testing"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/dns"

	D "github.com/miekg/dns"
)

func TestDNSReplacementRetiresOnlyConfiguredResolvers(t *testing.T) {
	oldDefault, oldProxy, oldDirect, oldSystem := resolver.DefaultResolver, resolver.ProxyServerHostResolver, resolver.DirectHostResolver, resolver.SystemResolver
	oldMapper, oldService, oldHosts := resolver.DefaultHostMapper, resolver.DefaultService, resolver.UseSystemHosts
	t.Cleanup(func() {
		updateDNS(&config.DNS{}, false)
		resolver.DefaultResolver, resolver.ProxyServerHostResolver, resolver.DirectHostResolver, resolver.SystemResolver = oldDefault, oldProxy, oldDirect, oldSystem
		resolver.DefaultHostMapper, resolver.DefaultService, resolver.UseSystemHosts = oldMapper, oldService, oldHosts
	})
	servers := []dns.NameServer{{Net: "rcode", Addr: "success"}}
	system := dns.NewResolver(dns.Config{Main: servers})
	defer system.CloseQueries()
	resolver.SystemResolver = system
	resolver.DefaultResolver, resolver.ProxyServerHostResolver, resolver.DirectHostResolver = nil, nil, nil
	resolver.DefaultHostMapper, resolver.DefaultService = nil, nil
	query := new(D.Msg)
	query.SetQuestion("reload.test.", D.TypeA)
	check := func(r resolver.Resolver, closed bool) {
		t.Helper()
		_, err := r.ExchangeContext(context.Background(), query.Copy())
		if closed && !errors.Is(err, context.Canceled) || !closed && err != nil {
			t.Fatalf("closed=%v, exchange error=%v", closed, err)
		}
	}
	cfg := &config.DNS{Enable: true, NameServer: servers, ProxyServerNameserver: servers, DirectNameServer: servers}
	updateDNS(cfg, true)
	previous := []resolver.Resolver{resolver.DefaultResolver, resolver.ProxyServerHostResolver, resolver.DirectHostResolver}
	for _, r := range previous {
		check(r, false)
	}
	updateDNS(cfg, true)
	for _, r := range previous {
		check(r, true)
	}
	check(system, false)
	current := []resolver.Resolver{resolver.DefaultResolver, resolver.ProxyServerHostResolver, resolver.DirectHostResolver}
	for _, r := range current {
		check(r, false)
	}
	updateDNS(&config.DNS{}, false)
	for _, r := range current {
		check(r, true)
	}
	if resolver.DefaultResolver != nil || resolver.ProxyServerHostResolver != nil || resolver.DirectHostResolver != nil || resolver.DefaultService != nil || resolver.DefaultHostMapper != nil {
		t.Fatal("disabled DNS retained retired configuration")
	}
	updateDNS(cfg, true)
	check(resolver.DefaultResolver, false)
	check(system, false)
}
