# Changelog

## Unreleased — v1.3.1

- MCP output schemas now advertise the exact eight allowed
  `signals_truncated_reasons` enum values (`links`, `signals`,
  `inline_scripts`, `window_names`, `headers`, `cookie_count`,
  `cookie_bytes`, `cookie_value`) on every homepage and secondary-page
  truncation array — enabling precise agent validation and autocomplete.
  Runtime JSON, CLI output, and detection remain unchanged.

## v1.3.0 — 2026-08-31

- Fingerprint transparency: extend `technograph fingerprints` with offline
  inspection filters `--technology` (repeatable, case-insensitive) and
  `--channel header|script|cookie|html|meta|js|dns_txt|dns_cname|dns_mx`
  (repeatable union) plus `--format json|table` (json default, byte-compatible
  `FingerprintInventory` with filtered count; table sanitizes tabs/newlines).
  Filtering is post-load `Load → Descriptors() → filters` — one canonical
  `fingerprint.Load` path.
- Strict validation: `technograph fingerprints --fingerprints <file> --validate`
  validates via `fingerprint.Load(strict=true)` (exit 0 valid no stdout,
  exit 1 invalid, exit 2 usage). Rejects `--technology/--channel/--format table/--output`
  when validating. Validates schema, limits, channels, regex, and strict-rejected
  patterns.
- Generated docs: add `docs/fingerprints.md` from bundled `fingerprints.json`
  via `fingerprint.Load(strict=true) → Descriptors()` with Markdown escaping,
  `16` technologies / `24` patterns table, channel/origin glossary, and
  `make fingerprints-doc` plus CI drift guard.
- No change to scanning, `fingerprints.json`, `output.json`, MCP, limits, or
  detection behavior.

## v1.2.0 — 2026-08-30

- Additive truncation reasons: structured reports include `http.signals_truncated`
  (existing) and deterministic `http.signals_truncated_reasons: []string`
  (`http.pages[].signals_truncated_reasons` for opt-in secondary pages). Allowed
  values are `links`, `signals`, `inline_scripts`, `window_names`, `headers`,
  `cookie_count`, `cookie_bytes`, `cookie_value` — sorted and deduplicated, only
  when a valid candidate was actually omitted or truncated. `SIGNALS_TRUNCATED`
  now includes the reasons (`detection may be incomplete: <reasons>`) and still
  maps to `partial` when `ok`. When truncated, detection may be incomplete.
  No change to the minimal `{domain:[technologies]}` assignment artifact.
- Limits intentionally unchanged; tuning requires evidence from live scans and
  profiling before any increase.

## v1.1.0 — 2026-08-30

- HTML extraction budgets: cap derived links (5,000), signals (5,000),
  inline scripts (50) and window names (512) per page; preserve `html:body`
  as the first signal. Truncation sets `http.signals_truncated` and, via
  `Runner`, a `SIGNALS_TRUNCATED` warning with `partial` status, including
  for opt-in secondary pages (`http.pages[].signals_truncated`).
- HTTP metadata budgets: `MaxResponseHeaderBytes=1 MiB`, header signals capped
  at 128, cookies at 100 / 4 KiB each / 32 KiB cumulatively across redirects
  (bounded jar with global counters including names/domain/path and a
  `truncated` flag). Oversize or dropped headers/cookies set
  `signals_truncated`.
- External fingerprint budgets: `10 MiB` file via bounded `LimitReader`,
  `20,000` technologies, `100,000` patterns, `2,048 B` regex; preserves
  compatibility with the full Wappalyzer corpus (`5,862 techs / 7,665 pats`).
- Safe-network IPv6: add 7 never-public prefixes (`64:ff9b:1::/48`,
  `fec0::/10`, `2002::/16`, `2001:10::/28`, `2001:20::/28`, `2001::/32`,
  `192.88.99.0/24`) with table-driven `IsPublic` tests; public IPv4/IPv6
  remain accepted.
- Domain suffix: document the open policy choice in `README.md`,
  `docs/agent-interface.md` and `internal/domain/domain.go` — `service.internal`
  parses but HTTP to private addresses is blocked while DNS queries are still
  sent; no behavior change until an explicit strict/allow decision.
- Supply-chain: pin `actions/checkout`, `actions/setup-go` and
  `goreleaser/goreleaser-action` to immutable SHAs with version comments.

## v1.0.1 — 2026-08-30

- Harden legacy networking: `technograph domains.txt` now uses `SafeNetwork: true`
  (`internal/cli/run.go:88-105`), matching the structured CLI and MCP defaults.
- Enforce request-ID limits: `Runner.Scan`/`ScanStream`
  (`internal/agentapi/runner.go:20,70-112,241-252`) reject IDs above 256 bytes;
  `history.Store.Save` (`internal/history/history.go:26,123-162,345-388`)
  independently enforces the same limit and validates entry size against the
  exact indented JSON bytes before commit. Oversized entries are rejected
  before they can poison the store.
- Bound history retention: `history.Store.Save` prunes the oldest file before
  a write would exceed `MaximumEntries=10,000` (`history.go:359-388`), keeping
  `Latest`/`History` readable. No change to CLI/MCP contracts or `output.json`.

## v1.0.0 — 2026-08-28

- Declare stable 1.x CLI, JSON/JSONL, schema, normalized-fingerprint, history,
  and MCP compatibility guarantees with documented exit statuses.
- Add golden structured-report and assignment-artifact contract tests plus JSON
  validation for every published schema.
- Add reproducible offline matcher/extractor benchmarks and fixed-iteration CI
  smoke benchmarks; pin canonical formatting to Go 1.25.7 across environments.
- Remove the completed internal implementation plan from the public deliverable
  and add concise contribution and release-quality documentation.
- Complete a clean Go 1.25/Go 1.27 test, race, vet, build, live assignment, MCP,
  release-archive, checksum, and Homebrew verification pass.

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
