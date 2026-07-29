#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
cd "$repo_root"

dns_auth_private_key="${MIHOMO_DNS_AUTH_PRIVATE_KEY:-}"
if [[ -z "$dns_auth_private_key" ]]; then
  dns_auth_private_key="$(git config --local --get custom.dnsAuthPrivateKey || true)"
fi

dns_auth_domains="${MIHOMO_DNS_AUTH_DOMAINS:-}"
if [[ -z "$dns_auth_domains" ]]; then
  dns_auth_domains="$(git config --local --get custom.dnsAuthDomains || true)"
fi

if [[ -z "$dns_auth_private_key" || -z "$dns_auth_domains" ]]; then
  echo "DNS-Auth build parameters are missing from the repository-local Git config." >&2
  echo "Set custom.dnsAuthPrivateKey and custom.dnsAuthDomains before building." >&2
  exit 1
fi

decoded_key_size="$(
  printf '%s' "$dns_auth_private_key" \
    | base64 --decode 2>/dev/null \
    | wc -c \
    | tr -d ' '
)"
if [[ "$decoded_key_size" != "32" ]]; then
  echo "custom.dnsAuthPrivateKey must decode to exactly 32 bytes." >&2
  exit 1
fi

target_goos="${GOOS:-$(go env GOOS)}"
target_goarch="${GOARCH:-$(go env GOARCH)}"
version="${MIHOMO_BUILD_VERSION:-custom-$(git rev-parse --short HEAD)}"
build_time="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
output_path="${1:-bin/mihomo-${target_goos}-${target_goarch}}"

mkdir -p "$(dirname "$output_path")"

ldflags="-X github.com/metacubex/mihomo/constant.Version=$version"
ldflags+=" -X github.com/metacubex/mihomo/constant.BuildTime=$build_time"
ldflags+=" -X github.com/metacubex/mihomo/component/resolver.GlobalDNSAuthPrivateKey=$dns_auth_private_key"
ldflags+=" -X github.com/metacubex/mihomo/component/resolver.GlobalDNSAuthDomains=$dns_auth_domains"
ldflags+=" -w -s -buildid="

CGO_ENABLED=0 GOOS="$target_goos" GOARCH="$target_goarch" \
  go build \
    -tags with_gvisor \
    -trimpath \
    -ldflags "$ldflags" \
    -o "$output_path" \
    .

chmod 700 "$output_path"
echo "Built $output_path with DNS-Auth enabled."
