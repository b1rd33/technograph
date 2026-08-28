# Changelog

## v0.9.0 — 2026-08-28

- Add the always-available MCP `explain_domain` tool, grouping each technology
  only with its exact matching evidence and carrying partial-scan issues.
- Add opt-in MCP `watch_domain` and `domain_history` tools when a human starts
  the server with a fixed `--history PATH`; agents cannot select storage paths.
- Share conservative baseline comparison and immutable observation logic
  between CLI and MCP, with serialized MCP history writes.
- Add an evidence-explanation schema and in-memory MCP round-trip tests for all
  default and history-enabled tool surfaces.

## v0.8.0 — 2026-08-28

- Add `technograph explore`, a dependency-free interactive terminal evidence
  explorer that scans once and never starts a web server or dashboard.
- Support filtering by domain, status, technology, or category and opening the
  exact deterministic evidence report for a numbered or named domain.
- Keep direct-domain, file input, custom fingerprints, DNS, safe-network,
  timeout, and opt-in page coverage controls aligned with the scanner CLI.
- Add deterministic transcript tests and a scripted live terminal review.

## v0.7.0 — 2026-08-28

- Add opt-in `--pages 1-5` coverage to `scan`, `explain`, and `watch` while
  preserving homepage-only behavior by default and in the assignment CLI/MCP.
- Follow a deterministic set of useful same-host public HTML links within the
  existing per-domain HTTP deadline; strip query/fragment duplicates and skip
  static assets, nonstandard ports, credentials, and cross-host redirects.
- Attribute matching evidence to its page URL and report secondary page
  coverage, blocks, truncation, and failures without discarding homepage/DNS
  evidence.
- Include page coverage in watch compatibility identity so changing `--pages`
  establishes a new baseline instead of a false technology change.

## v0.6.0 — 2026-08-28

- Add one-shot `watch` scans backed by immutable private local observations and
  newest-first offline `history` queries.
- Reset comparison baselines when scanner or fingerprint identities change,
  preventing upgrades from appearing as website technology changes.
- Preserve conservative removal suppression for blocked/partial scans and add
  optional exit status 3 for scheduler-owned change notifications.
- Add bounded/corruption-aware storage, history/watch schemas, live two-cycle
  verification, and automation documentation.

## v0.5.0 — 2026-08-28

- Add an offline native Wappalyzer importer for files or complete technology
  directories, with exact technology filters and optional category resolution.
- Preserve native header, cookie, and meta selectors before matching values,
  including empty-pattern presence checks.
- Validate every imported Wappalyzer tag and regex with RE2, deduplicate exact
  normalized rules, and emit a deterministic issue for every skipped pattern.
- Add strict import mode, normalized-database and compatibility-report schemas,
  full-corpus measurements, and end-to-end generated-database tests.

## v0.4.0 — 2026-08-28

- Add deterministic table and spreadsheet-safe CSV scan output while retaining
  the existing JSON and completion-order JSONL contracts.
- Add optional technology categories to bundled and external fingerprint
  definitions, structured results, inventory, human reports, and exports.
- Add repeatable, local-only custom DNS resolver flags with strict literal-IP
  and port validation; MCP continues to use system DNS.
- Preserve the original assignment output and conservative matching rules.

## v0.3.1 — 2026-08-28

- Explain the CLI's purpose, command choices, and human/JSON/MCP interfaces in
  top-level help.
- Add practical examples and behavior notes to every subcommand's help.
- Document all four MCP tools, local client configuration, and safety defaults
  in `technograph-mcp --help`.

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
