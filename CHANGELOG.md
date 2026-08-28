# Changelog

## v0.3.0 — 2026-08-28

- Add `technograph explain` for deterministic human-readable technology
  evidence, HTTP/DNS coverage, and partial or blocked scan diagnostics.
- Support the same direct-domain, stdin, file, network-policy, timeout, and
  atomic output controls as the structured scanner.
- Escape terminal control characters in all network-derived report text.

## v0.2.2 — 2026-08-27

- Retry partially decoded UDP DNS responses over TCP without extending the
  configured per-resolver timeout.
- Preserve fast resolver fallback for transport failures that return no DNS
  response.
- Add regression coverage for DNS decode errors, TCP failure isolation, and
  gzip decompression before response body limits.
- Clarify how redirect-set cookies can contribute signals at the final URL.

## v0.2.1 — 2026-08-27

- Make `-h` and `--help` succeed with exit status 0 across the main CLI,
  structured subcommands, and the MCP binary.
- Send help text to stdout while keeping invalid-usage diagnostics on stderr.
- Preserve literal positional arguments after the standard `--` delimiter.
- Add regression tests for help, version, stream, and invalid-argument behavior.

## v0.2.0 — 2026-08-27

- Preserve the original v0.1 file-based assignment command and required JSON.
- Add direct-domain, stdin, JSON, and completion-order JSONL scan interfaces.
- Add versioned typed statuses, warnings, errors, evidence, and JSON schemas.
- Add domain validation and embedded fingerprint inventory commands.
- Add conservative snapshot comparison that suppresses uncertain removals.
- Add public-address resolution and IP pinning for autonomous SSRF protection.
- Add the separate `technograph-mcp` stdio server with four read-only tools.
- Add per-request and process-wide 20-domain limits with atomic acquisition.
- Add automation guidance, MCP integration tests, and two-binary release archives.

## v0.1.0 — 2026-08-27

- Initial production-quality implementation of the technographic detection
  assignment.
- HTTP, HTML, script, cookie, meta, static JavaScript, and DNS signal channels.
- Conservative Wappalyzer-style matching, evidence reports, soft-block
  handling, bounded concurrency, deterministic required output, tests, GitHub
  releases, and Homebrew installation.
