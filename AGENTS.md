# Local custom builds

- On the `custom` branch, build runnable binaries with `./scripts/build-custom-local.sh` or `make custom-local`.
- Do not use a bare `go build` for connectivity testing: it omits the required DNS-Auth linker values.
- The build helper reads `custom.dnsAuthPrivateKey` and `custom.dnsAuthDomains` from the repository-local Git config (`.git/config`). These values must remain untracked and must never be printed, copied into tracked files, or included in diagnostics.
- `go test` does not require DNS-Auth linker values.

# Custom compatibility invariants

- Keep the custom Controller `/proxies` behavior across upstream merges: `GET /proxies` must include runtime proxies **and every loaded proxy-provider node**. `GET /proxies/{name}` (including its delay endpoint) must also resolve provider nodes. Provider nodes take precedence if a name collides with a runtime proxy. Do not replace this with upstream's runtime-only `/proxies`; `/providers/proxies` remains available separately. Run `go test ./hub/route` after changes to the Controller or provider handling.
- Keep DNS-Auth working across upstream DNS changes. The proxy-server host resolver must be wrapped by `resolver.WrapDNSAuthResolver` after the optional `WrapProxyServerResolver` hook is installed, before providers load. Preserve signed A/AAAA and ECH lookups for managed suffixes, the existing signing format, and DNS reload behavior. Run `go test ./component/resolver ./hub/executor` after DNS or resolver changes; for runnable connectivity checks, use the custom local build helper above so the DNS-Auth linker values are present.
- Keep TUN `system` TCP keepalive configurable across upstream merges: accepted TUN `system` TCP connections must use the current global `keep-alive-idle`, `keep-alive-interval`, and `disable-keep-alive` settings, not Go's fixed 15-second accepted-socket defaults. Preserve the `listener/sing_tun` -> `third_party/sing-tun` `StackOptions.TCPKeepAlive` hook and apply it on each accepted connection so config reloads affect new connections. Existing connections retain their socket settings; other TUN stacks are unchanged. Run `go test ./component/keepalive ./listener/sing_tun` and the `third_party/sing-tun` system-stack tests after changes to this path.
