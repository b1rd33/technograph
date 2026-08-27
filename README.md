# Technograph

Technograph is a conservative, HTTP-only technographic detection CLI and local
MCP server. It reads company domains, observes their public homepage and apex
DNS records, and matches those signals against Wappalyzer-style fingerprints.

The original technical-home-assignment interface is preserved unchanged. v0.2
adds a versioned JSON/JSONL interface, typed partial-failure states,
snapshot comparison, SSRF protection for autonomous callers, and a separate
stdio MCP binary. The immutable assignment submission is tagged `v0.1.0`.

It does not execute JavaScript, use a headless browser, call a paid API, or try
to bypass bot protection.

## Installation

### Homebrew

```console
brew install b1rd33/tap/technograph
technograph --version
```

Upgrade later releases with `brew upgrade technograph`.

The formula installs both `technograph` and `technograph-mcp`. Homebrew handles
the Go build dependency automatically; Go is not needed when using the
installed binaries afterward.

### Build from source

- Go 1.25 or newer
- Network access to public HTTP(S) endpoints and the system DNS resolver

```console
git clone https://github.com/b1rd33/technograph.git
cd technograph
make build
```

The binaries are written to `bin/technograph` and `bin/technograph-mcp`.
Dependencies are pinned in `go.mod` and `go.sum`.

Prebuilt archives and checksums for macOS and Linux on ARM64 and AMD64 are also
available from the [GitHub releases](https://github.com/b1rd33/technograph/releases).

## Original assignment usage

Put one bare domain on each line of a text file, then run:

```console
./bin/technograph -output output.json domains.txt
```

The committed assignment scan can be reproduced with:

```console
./bin/technograph \
  -output output.json \
  -report report.json \
  -concurrency 10 \
  -timeout 8s \
  -dns-timeout 3s \
  domains.txt
```

Available options:

| Flag | Default | Purpose |
| --- | --- | --- |
| `-output` | `output.json` | Required technology-only JSON artifact |
| `-report` | empty | Optional diagnostics and evidence JSON |
| `-concurrency` | `10` | Maximum domains scanned simultaneously |
| `-timeout` | `8s` | HTTP request deadline per domain |
| `-dns-timeout` | `3s` | Deadline per DNS record query |
| `-fingerprints` | embedded | External normalized fingerprint file |
| `-insecure` | false | Explicitly disable TLS verification |
| `-verbose` | false | Show DNS and soft-block diagnostics |

Diagnostics go to stderr. A failed or blocked individual domain does not abort
the batch; configuration, input, fingerprint, and output errors return a
nonzero exit status.

## Agent and automation usage

The structured interface accepts direct domains, stdin, or a file. Flags may
appear before or after positional domains:

```console
technograph scan stripe.com shopify.com --format json
printf 'stripe.com\nshopify.com\n' | technograph scan --format jsonl
technograph scan --input domains.txt --output snapshot.json
technograph validate example.com https://invalid.example
technograph fingerprints
technograph compare before.json after.json --output diff.json
```

JSON output uses schema version `1.0` and gives every input an `ok`, `partial`,
`blocked`, `failed`, or `invalid` status plus typed warnings/errors. JSONL emits
domain results in actual completion order. Logs stay on stderr, so stdout is
safe to pipe into agents and automation.

The separate `technograph-mcp` binary serves four local stdio tools:
`scan_domain`, `scan_domains`, `validate_domain`, and `list_fingerprints`.

```json
{
  "mcpServers": {
    "technograph": { "command": "technograph-mcp" }
  }
}
```

See [docs/agent-interface.md](docs/agent-interface.md) for the complete contract,
[docs/automation.md](docs/automation.md) for scheduling patterns, and
[schemas/scan-report.schema.json](schemas/scan-report.schema.json) for the
machine-readable schema. No Codex/ChatGPT skill is created or required.

## Output

The required file contains every valid input domain, including domains for
which no technology was detected:

```json
{
  "example.com": ["Cloudflare", "Google Workspace"],
  "unreachable.example": []
}
```

Technology names are sorted. Domain order follows the deduplicated input.
Files are written to a temporary sibling and atomically renamed, so an
interrupted run does not leave a partial JSON file.

`-report` adds final HTTP status, redirect and block information, exact DNS
records, elapsed time, and evidence for every match. The report is deliberately
separate so the required submission shape stays exact.

## Architecture

The implementation is divided into small packages:

- `internal/cli` validates bare domains, normalizes IDNs, derives registrable
  apexes with the Public Suffix List, and preserves the original command.
- `internal/app` constructs the reusable scanner used by every interface.
- `internal/agentapi` defines the versioned status, report, streaming, and diff
  contracts; `internal/agentcli` exposes them as structured subcommands.
- `internal/probe` fetches homepages and performs exact MX, TXT, and apex CNAME
  queries. HTTPS is preferred; HTTP fallback occurs only for transport/TLS
  failures. DNS uses the system resolver configuration, nameserver failover,
  UDP first, and TCP retry for truncated replies.
- `internal/extract` produces structured signals from final response headers,
  cookie names/values, raw HTML, script URLs and bounded inline source, meta
  fields, and static `window.*` syntax. Relative script URLs are resolved
  against the final response URL.
- `internal/fingerprint` compiles patterns once, indexes them by channel, and
  returns sorted technologies plus auditable evidence. There is no
  technology-specific matching code.
- `internal/scanner` uses a bounded domain worker pool. HTTP and DNS run in
  parallel inside each domain job, each with a hard parent deadline. Results
  retain input order and partial successes.
- `internal/output` creates deterministic required JSON and detailed reports.
- `internal/policy` resolves and pins public addresses for autonomous HTTP
  requests while rejecting private, loopback, link-local, metadata, multicast,
  documentation, and other special-use networks.
- `internal/mcpserver` exposes a small read-only tool surface using the official
  Go MCP SDK. MCP dependencies and protocol output are isolated in the separate
  `technograph-mcp` executable.

The supplied fingerprint file uses a normalized representation because the
assignment's header and cookie expressions match names, while native
Wappalyzer normally uses exact names as selectors and applies regexes to their
values. Every rule therefore has an explicit `channel`, `regex`, and optional
`target` (`name` or `value`). A technology is detected when any of its patterns
matches a signal in the same channel. Evidence and technology names are
deduplicated.

## Accuracy and block handling

Accuracy is intentionally favored over recall:

- only the final response contributes HTTP signals;
- TLS verification is enabled unless the user explicitly opts out;
- response bodies are capped after decompression;
- confirmed challenge pages are recorded but their HTML/script/meta signals
  are suppressed;
- final headers, cookies, and DNS remain usable when HTML is blocked;
- HTTPS does not fall back to HTTP for ordinary 4xx/5xx responses;
- DNS record types fail independently.

A Cloudflare-protected site is therefore not a fatal condition. `cf-ray` or
`cf-cache-status` can still detect Cloudflare itself, DNS still runs, and the
scanner safely avoids claiming technologies from a Cloudflare challenge body.
This may produce false negatives for technologies visible only after browser
execution or only in protected HTML, which is the correct trade-off for this
assignment.

Structured CLI scans enable the autonomous network policy by default. It
revalidates every connection and redirect, pins the validated address, allows
only ports 80/443, and ignores proxy environment variables. A clearly named
`--allow-private-network` escape hatch exists for trusted local CLI testing;
it is deliberately unavailable through MCP. MCP also caps each request and
global active work at 20 domains and accepts only embedded fingerprints.

## Fingerprint compatibility

Technograph implements its own matcher; Wappalyzer is not a runtime dependency.
Patterns are case-insensitive and support Wappalyzer's escaped
`\\;confidence:N` and `\\;version:...` metadata (version templates are retained
for future version reporting). Go's RE2 engine supports all 24 supplied
patterns and 13,710 of 13,724 current upstream patterns measured across the
relevant pattern-bearing fields (99.90%). The 14 unsupported JavaScript
lookaround expressions are reported when loading an external file rather than
silently rewritten. Full details and methodology are in
`docs/wappalyzer-compatibility.md`.

The scanner implements static HTTP/DNS channels only. Runtime DOM inspection,
executed JavaScript globals, XHR observation, TLS certificates, robots files,
and secondary-page crawling are outside scope. Public pages and DNS records
also change over time, so real results are observations, not permanent facts.

## Testing

```console
make fmt
make vet
make test
make race
make build
```

The suite covers domain validation and fuzzing, all supplied fingerprints,
wrong-channel negatives, structured extraction, redirects, TLS/HTTP fallback,
compression, body limits, challenge suppression, DNS normalization and TCP
retry, bounded and completion-order concurrency, deterministic legacy JSON,
typed agent output, conservative diffs, SSRF address policy, atomic output, and
an in-memory MCP client/server integration test.

## Included real scan

`output.json` is the raw, unedited result of scanning the exact 20 domains in
`domains.txt` on 2026-08-27 (Europe/Sofia) using Go 1.27.0 on Darwin/arm64,
concurrency 10, an 8-second HTTP timeout, and a 3-second per-query DNS timeout.
The final measured wall time was 4.064 seconds. All 20 domains were emitted; there
were zero HTTP transport failures and one detected challenge response.
