# Contributing

Keep detection conservative and generic. Technology-specific behavior belongs
in fingerprint data, not Go conditionals. Every new signal or matcher behavior
needs a positive test, a wrong-channel or false-positive test, and evidence that
explains the resulting claim.

Before opening a change:

```console
make fmt
make vet
make test
make race
make benchmark
make build
```

Formatting is pinned to Go 1.25.7 so output is identical across developer Go
versions. Runtime compatibility remains Go 1.25 or newer.

Do not add a headless browser, paid detection API, CAPTCHA/block bypass, hidden
network expansion, or unbounded crawl. Preserve the v0.1 assignment interface
and follow [docs/stability.md](docs/stability.md) for 1.x contracts.
