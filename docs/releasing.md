# Release process

1. Confirm `main` is clean and CI is green.
2. Run `make release-check`, `make test`, `make race`, and `make benchmark`.
3. Tag the release with `git tag -a vX.Y.Z -m "technograph vX.Y.Z"` and push the tag.
4. Wait for the Release workflow to publish all four platform archives and
   `checksums.txt`. Each archive must contain `technograph`,
   `technograph-mcp`, `LICENSE`, and `README.md`.
5. Download the release assets and verify `shasum -a 256 -c checksums.txt`.
6. Update `technograph.rb` in `b1rd33/homebrew-tap` with the version, archive
   URLs, and verified platform checksums.
7. Install with `brew install b1rd33/tap/technograph`, run both binaries with
   `--version`, run `brew test b1rd33/tap/technograph`, perform a sample CLI
   scan, and connect an MCP client to `technograph-mcp`.

The tap update is intentionally performed after release verification. The
GitHub Actions token is scoped to this repository, and no broad account token
is persisted as a cross-repository secret.
