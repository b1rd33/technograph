# Technographic Detection CLI — TODO

This checklist is the execution companion to [PLAN.md](./PLAN.md). Tasks are
ordered so each phase leaves the repository in a verified state. Complete one
phase and its gate before starting the next.

## Phase 0 — Confirm fingerprint compatibility

- [x] Inspect the native Wappalyzer technology and pattern formats.
- [x] Record the relevant channel shapes and supported pattern directives.
- [x] Put all 24 assignment patterns into a temporary Go compilation test.
- [x] Confirm all 24 compile with Go `regexp`.
- [x] Sample representative upstream Wappalyzer patterns for unsupported RE2
      syntax.
- [x] Define the honest compatibility statement for the README.
- [x] Decide the minimal internal regex interface; do not add a second engine
      without measured justification.
- [x] Gate: document the supported pattern boundary before building the loader.

## Phase 1 — Create the Go project

- [x] Initialize the Go module.
- [x] Create `cmd/technograph` and the required `internal` packages.
- [x] Add `.gitignore`.
- [x] Add a Makefile with `fmt`, `vet`, `test`, `race`, `build`, and `scan`.
- [x] Add the exact 20 domains to `domains.txt`.
- [x] Add the exact 24 fingerprints to `fingerprints.json`.
- [x] Embed the default fingerprints with `go:embed`.
- [x] Add a minimal CLI entry point that builds.
- [x] Gate: `go build ./cmd/technograph` succeeds.

## Phase 2 — Parse and normalize domains

- [x] Read one domain per line.
- [x] Ignore blank lines and full-line comments.
- [x] Validate hostnames and reject paths, schemes, ports, IPs, and malformed
      input.
- [x] Normalize Unicode domains with IDNA.
- [x] Normalize DNS case and trailing dots.
- [x] Derive the apex with the Public Suffix List.
- [x] Preserve normalized submitted domains as output keys.
- [x] Deduplicate domains while preserving first occurrence.
- [x] Include source line numbers in validation errors.
- [x] Add table-driven domain parser tests.
- [x] Add a domain-parser fuzz test.
- [x] Gate: invalid input fails before any network request.

## Phase 3 — Define signals and evidence

- [x] Define channel constants.
- [x] Define structured header name/value signals.
- [x] Define structured cookie name/value signals.
- [x] Define HTML, script, meta, JS, MX, TXT, and CNAME signals.
- [x] Store signal origin for auditing.
- [x] Define fingerprint, compiled-pattern, evidence, and scan-result types.
- [x] Preserve case except where protocol semantics require normalization.
- [x] Add channel-isolation tests.
- [x] Gate: header names, header values, cookie names, and cookie values cannot
      be confused by the matcher.

## Phase 4 — Build the fingerprint engine

- [x] Load embedded fingerprints by default.
- [x] Support an external fingerprint file override.
- [x] Accept a single pattern or list of patterns per channel.
- [x] Parse supported Wappalyzer confidence/version directives.
- [x] Compile patterns once during startup.
- [x] Return contextual errors for malformed patterns.
- [x] Index compiled patterns by channel.
- [x] Match assignment headers and cookies against names.
- [x] Implement OR semantics across technology patterns.
- [x] Deduplicate evidence and technology names.
- [x] Sort detected technologies.
- [x] Add positive tests for all 24 supplied patterns.
- [x] Add negative and wrong-channel tests.
- [x] Add the negative Cloudflare header-value test.
- [x] Add directive and unsupported-regex tests.
- [x] Gate: all matching tests pass with no technology-specific Go code.

## Phase 5 — Extract static page signals

- [x] Parse HTML with `golang.org/x/net/html`.
- [x] Retain a bounded raw HTML signal.
- [x] Extract raw script `src` values.
- [x] Resolve relative and protocol-relative script URLs.
- [x] Extract bounded inline script source.
- [x] Treat inline source as part of the script channel for `gtag\(`.
- [x] Extract meta names/properties and content separately.
- [x] Parse final-host cookie names and values.
- [x] Decide whether static `window.*` syntax adds enough value to include.
- [x] Add malformed HTML, URL resolution, inline script, and meta tests.
- [x] Gate: required HTTP-visible channels are extracted without JavaScript
      execution.

## Phase 6 — Implement the HTTP probe

- [x] Create one reusable configured HTTP client and transport.
- [x] Use an honest `technograph` User-Agent.
- [x] Request HTTPS first.
- [x] Fall back to HTTP only on transport or TLS failure.
- [x] Add a strict redirect limit.
- [x] Keep redirect history for diagnostics only.
- [x] Use a cookie jar and retain only cookies applicable to the final host.
- [x] Enable TLS verification by default.
- [x] Add an explicit insecure option.
- [x] Configure connect, TLS, header, idle, and total request deadlines.
- [x] Limit the decompressed body using `io.LimitReader(max+1)`.
- [x] Detect and record body truncation.
- [x] Parse HTML media types and add conservative HTML sniffing.
- [x] Close every response body.
- [x] Define conservative soft-block and challenge criteria.
- [x] Suppress HTML-derived signals for confirmed challenge pages.
- [x] Preserve final headers and relevant cookies on blocked responses.
- [x] Add `httptest` coverage for success, redirects, failures, fallback,
      content types, compression, truncation, and challenges.
- [x] Gate: HTTP behavior is bounded and blocked pages cannot produce
      challenge-body technology detections.

## Phase 7 — Implement DNS collection

- [x] Read the supported system DNS resolver configuration.
- [x] Document the supported operating-system behavior.
- [x] Query the derived apex as an FQDN.
- [x] Query MX, TXT, and CNAME concurrently.
- [x] Use configured nameserver failover.
- [x] Use UDP first and retry truncated responses over TCP.
- [x] Apply a context deadline per DNS query.
- [x] Collect exact answer RRsets.
- [x] Normalize MX exchanges.
- [x] Join fragments within one TXT RR while preserving separate records.
- [x] Normalize CNAME targets.
- [x] Deduplicate DNS records.
- [x] Distinguish NXDOMAIN, NODATA, timeout, and resolver failure internally.
- [x] Treat an empty apex CNAME response as normal.
- [x] Add injected-resolver tests for every record and failure path.
- [x] Gate: failure of one record type does not hide successful DNS evidence.

## Phase 8 — Orchestrate concurrent scanning

- [x] Implement a bounded domain worker pool.
- [x] Default to 10 workers.
- [x] Give every domain a hard parent context deadline.
- [x] Run HTTP and DNS concurrently per domain.
- [x] Preserve input order in collected results.
- [x] Include every valid domain on partial or total failure.
- [x] Ensure cancellation does not leak goroutines.
- [x] Make any whole-scan deadline scale with input size, concurrency, and the
      per-domain deadline.
- [x] Add concurrency, cancellation, isolation, and ordering tests.
- [x] Gate: offline tests prove bounded concurrency and a calculable runtime
      ceiling.

## Phase 9 — Finish the CLI and JSON output

- [x] Implement flags before the positional input file.
- [x] Add output, concurrency, HTTP timeout, DNS timeout, fingerprints,
      evidence report, insecure, and verbosity options.
- [x] Keep diagnostics on stderr.
- [x] Produce exactly `{ "domain": ["Technology"] }` in `output.json`.
- [x] Serialize no-match domains as `[]`, never `null`.
- [x] Sort technology names.
- [x] Preserve deterministic domain ordering.
- [x] Write through a temporary file in the destination directory.
- [x] Atomically rename the completed output.
- [x] Return nonzero for input/config/output errors.
- [x] Complete successfully when individual domains fail.
- [x] Add golden output and CLI integration tests.
- [x] Gate: mocked end-to-end execution produces byte-stable required JSON.

## Phase 10 — Run the quality suite

- [x] Run `go fmt ./...`.
- [x] Run `go vet ./...`.
- [x] Run `go test ./...`.
- [x] Run `go test -race ./...`.
- [x] Run `go build ./cmd/technograph`.
- [x] Review dependencies and licenses.
- [x] Review response-body closure and context cancellation.
- [x] Review every matching path for false-positive risk.
- [x] Test the built binary from a clean directory.
- [x] Gate: formatting, vet, tests, race tests, and build all pass.

## Phase 11 — Produce and audit the real scan

- [x] Build the release binary.
- [x] Run the exact 20-domain input.
- [x] Record timestamp, Go version, OS/architecture, concurrency, and timeouts.
- [x] Measure total wall-clock duration.
- [x] Generate the real, unedited `output.json`.
- [x] Generate the optional evidence report.
- [x] Audit every detection against its exact signal and fingerprint.
- [x] Correct only generic logic; add no domain-specific exceptions.
- [x] Record successful responses, soft blocks, HTTP failures, and detection
      count.
- [x] Repeat the scan to understand external variability.
- [x] Gate: all 20 domains are present, all matches have evidence, and the scan
      finishes in under 60 seconds.

## Phase 12 — Complete the submission

- [x] Write installation and build instructions.
- [x] Document CLI usage and flags.
- [x] Explain the architecture and concurrency model.
- [x] Document signal channels and matching semantics.
- [x] Explain the Go decision briefly.
- [x] State the measured Wappalyzer compatibility boundary.
- [x] Explain redirect attribution and soft-block handling.
- [x] Document limitations and expected false negatives.
- [x] Include the real scan timestamp and benchmark details.
- [x] Note that public HTTP and DNS observations change over time.
- [x] Verify `domains.txt` contains exactly the assignment domains.
- [x] Verify `output.json` is the actual scan result.
- [x] Remove binaries, temporary files, and debug output.
- [x] Run the complete quality suite one final time.
- [x] Review the repository as a fresh evaluator following only the README.
- [x] Gate: the repository contains source, README, domains, and actual output
      and is ready to submit through GitHub.

## Final acceptance

- [x] No headless browser or JavaScript execution.
- [x] No paid external API.
- [x] No bot-protection bypass.
- [x] At least four required signal channels work.
- [x] All supplied fingerprints are represented exactly.
- [x] Matching is data-driven and evidence-backed.
- [x] Soft blocks and failures do not crash the scan.
- [x] Every domain appears in the required JSON shape.
- [x] The default 20-domain scan completes in under 60 seconds.
- [x] The committed output is real and unedited.
- [x] README and tests support every material implementation claim.
