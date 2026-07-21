package resolver

import (
	"context"
	"crypto/ed25519"
	"encoding/base32"
	"encoding/base64"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"
)

const (
	dnsAuthWindowSeconds = int64(300)
)

var (
	// Set at build time with -ldflags -X or overridden by the matching runtime environment variables.
	GlobalDNSAuthPrivateKey = ""
	GlobalDNSAuthDomains    = ""

	dnsAuthEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)
	dnsAuthOnce     sync.Once
	dnsAuthConfig   *dnsAuthSettings
)

type dnsAuthSettings struct {
	privKey  ed25519.PrivateKey
	suffixes []string
}

type dnsAuthResolver struct {
	Resolver
}

func WrapDNSAuthResolver(r Resolver) Resolver {
	if r == nil {
		return nil
	}
	if _, ok := r.(*dnsAuthResolver); ok {
		return r
	}
	settings := getDNSAuthSettings()
	if settings == nil {
		return r
	}
	log.Infoln("[DNS-Auth] proxy server host resolver enabled (ed25519) for %d managed suffix(es)", len(settings.suffixes))
	return &dnsAuthResolver{Resolver: r}
}

func (r *dnsAuthResolver) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.Resolver.LookupIP(ctx, tokenizeDNSAuthHost(host))
}

func (r *dnsAuthResolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.Resolver.LookupIPv4(ctx, tokenizeDNSAuthHost(host))
}

func (r *dnsAuthResolver) LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.Resolver.LookupIPv6(ctx, tokenizeDNSAuthHost(host))
}

func (r *dnsAuthResolver) ResolveECH(ctx context.Context, host string) ([]byte, error) {
	return r.Resolver.ResolveECH(ctx, tokenizeDNSAuthHost(host))
}

func getDNSAuthSettings() *dnsAuthSettings {
	dnsAuthOnce.Do(func() {
		if disabled := strings.ToLower(strings.TrimSpace(os.Getenv("MIHOMO_DNS_AUTH_ENABLED"))); disabled == "0" || disabled == "false" || disabled == "no" {
			return
		}

		domains := strings.TrimSpace(os.Getenv("MIHOMO_DNS_AUTH_DOMAINS"))
		if domains == "" {
			domains = GlobalDNSAuthDomains
		}
		suffixes := parseDNSAuthSuffixes(domains)
		if len(suffixes) == 0 {
			return
		}

		privateKeyText := strings.TrimSpace(os.Getenv("MIHOMO_DNS_AUTH_PRIVATE_KEY"))
		if privateKeyText == "" {
			privateKeyText = GlobalDNSAuthPrivateKey
		}
		seed, err := base64.StdEncoding.DecodeString(privateKeyText)
		if err != nil || len(seed) != ed25519.SeedSize {
			log.Warnln("[DNS-Auth] invalid private key")
			return
		}

		dnsAuthConfig = &dnsAuthSettings{
			privKey:  ed25519.NewKeyFromSeed(seed),
			suffixes: suffixes,
		}
	})
	return dnsAuthConfig
}

func parseDNSAuthSuffixes(domains string) []string {
	seen := make(map[string]struct{})
	suffixes := make([]string, 0)
	for _, domain := range strings.Split(domains, ",") {
		suffix := strings.ToLower(strings.TrimSpace(domain))
		suffix = strings.TrimPrefix(suffix, "*.")
		suffix = strings.TrimSuffix(suffix, ".")
		if suffix == "" || strings.Contains(suffix, "*") {
			continue
		}
		if _, ok := seen[suffix]; ok {
			continue
		}
		seen[suffix] = struct{}{}
		suffixes = append(suffixes, suffix)
	}
	return suffixes
}

func tokenizeDNSAuthHost(host string) string {
	settings := getDNSAuthSettings()
	if settings == nil || host == "" {
		return host
	}

	trimmedDot := strings.HasSuffix(host, ".")
	name := strings.ToLower(strings.TrimSuffix(host, "."))
	baseName, ok := settings.baseName(name)
	if !ok || settings.privKey == nil {
		return host
	}

	window := time.Now().Unix() / dnsAuthWindowSeconds
	p1, p2 := computeDNSAuthToken(settings.privKey, baseName, window)
	tokenized := p1 + "." + p2 + "." + baseName
	if trimmedDot {
		return tokenized + "."
	}
	return tokenized
}

func (s *dnsAuthSettings) baseName(name string) (string, bool) {
	if !s.matchSuffix(name) {
		return "", false
	}

	parts := strings.SplitN(name, ".", 3)
	if len(parts) == 3 && looksLikeDNSAuthTokenPart(parts[0]) && looksLikeDNSAuthTokenPart(parts[1]) && s.matchSuffix(parts[2]) {
		return parts[2], true
	}
	return name, true
}

func (s *dnsAuthSettings) matchSuffix(name string) bool {
	for _, suffix := range s.suffixes {
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return true
		}
	}
	return false
}

func looksLikeDNSAuthTokenPart(label string) bool {
	if len(label) != 52 {
		return false
	}
	for _, r := range label {
		if (r >= 'a' && r <= 'z') || (r >= '2' && r <= '7') {
			continue
		}
		return false
	}
	return true
}

func dnsAuthMessage(basename string, window int64) []byte {
	b := make([]byte, 0, len(basename)+1+20)
	b = append(b, basename...)
	b = append(b, '|')
	b = strconv.AppendInt(b, window, 10)
	return b
}

func computeDNSAuthToken(privateKey ed25519.PrivateKey, basename string, window int64) (string, string) {
	sig := ed25519.Sign(privateKey, dnsAuthMessage(basename, window))
	half := ed25519.SignatureSize / 2
	p1 := strings.ToLower(dnsAuthEncoding.EncodeToString(sig[:half]))
	p2 := strings.ToLower(dnsAuthEncoding.EncodeToString(sig[half:]))
	return p1, p2
}
