# Local custom builds

- On the `custom` branch, build runnable binaries with `./scripts/build-custom-local.sh` or `make custom-local`.
- Do not use a bare `go build` for connectivity testing: it omits the required DNS-Auth linker values.
- The build helper reads `custom.dnsAuthPrivateKey` and `custom.dnsAuthDomains` from the repository-local Git config (`.git/config`). These values must remain untracked and must never be printed, copied into tracked files, or included in diagnostics.
- `go test` does not require DNS-Auth linker values.
