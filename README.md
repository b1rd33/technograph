# Technograph

Technograph is a conservative, HTTP-only technographic detection CLI and local
MCP server. It reads company domains, observes their public homepage and apex
DNS records, and matches those signals against Wappalyzer-style fingerprints.

The original technical-home-assignment interface is preserved unchanged.
Later releases add versioned machine output, human and spreadsheet views,
typed partial-failure states, snapshot comparison, SSRF protection for
autonomous callers, and a separate stdio MCP binary. The immutable assignment
submission is tagged `v0.1.0`.

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
| `-dns-server` | system | Custom resolver IP and optional port; repeatable |
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
technograph explain stripe.com shopify.com
technograph explore stripe.com shopify.com
technograph explain stripe.com --pages 3
technograph scan stripe.com shopify.com --format table
technograph scan --input domains.txt --format csv --output results.csv
printf 'stripe.com\nshopify.com\n' | technograph scan --format jsonl
technograph scan --input domains.txt --output snapshot.json
technograph validate example.com https://invalid.example
technograph fingerprints
technograph fingerprints import --input webappanalyzer/src/technologies --output generated.json --report compatibility.json
technograph compare before.json after.json --output diff.json
technograph watch stripe.com --store .technograph-history
technograph history stripe.com --store .technograph-history
```

JSON output uses schema version `1.0` and gives every input an `ok`, `partial`,
`blocked`, `failed`, or `invalid` status plus typed warnings/errors. JSONL emits
domain results in actual completion order. Logs stay on stderr, so stdout is
safe to pipe into agents and automation. `table` is a compact terminal summary;
`csv` emits one spreadsheet-safe row per domain. Both preserve input order.

Detections include optional `technology_categories` metadata such as Payments,
Analytics, CRM, or CDN. Categories describe the technology; they never create
a detection and therefore do not change the conservative matching behavior.

`technograph explain` runs the same evidence-based scan but formats the result
for people: detections are grouped with their matching channel and source,
followed by HTTP/DNS coverage and any partial or blocked conditions. It does
not introduce a second detection path or an AI-generated confidence score.

`technograph explore` scans once and opens a lightweight interactive terminal
view over that same report. `filter payments`, `show 1`, `show stripe.com`,
`list`, and `clear` make live reviews easier without introducing a web
dashboard, a local server, or another dependency. Use positional domains or
`--input domains.txt`; standard input is reserved for explorer commands.

`technograph watch` is also one-shot: it compares a fresh scan with compatible
immutable local history, stores the observation, and exits. Confirmed changes
are structured separately from uncertain removals. `--fail-on-change` returns
status 3 after writing the report, which lets an external scheduler send a
notification without giving Technograph notification credentials. `history`
reads those private local entries without network access.

Homepage-only scanning remains the default. Local CLI users can opt into a
small deterministic crawl with `--pages 2` through `--pages 5` on `scan`,
`explain`, or `watch`. Secondary requests stay on the exact final homepage
host, use only public HTTP(S) ports, skip static assets, share the original
per-domain HTTP deadline, and never execute JavaScript. Evidence from an
opt-in scan includes the page URL. A secondary failure makes the structured
result partial but preserves valid homepage and DNS observations.

The separate `technograph-mcp` binary always serves five local stdio tools:
`scan_domain`, `scan_domains`, `explain_domain`, `validate_domain`, and
`list_fingerprints`. `explain_domain` groups every technology only with its
actual matching evidence; it never asks a language model to invent confidence.

```json
{
  "mcpServers": {
    "technograph": { "command": "technograph-mcp" }
  }
}
```

Starting the server with a human-chosen fixed history directory adds
`watch_domain` and `domain_history`:

```json
{
  "mcpServers": {
    "technograph": {
      "command": "technograph-mcp",
      "args": ["--history", "/absolute/path/to/history"]
    }
  }
}
```

The agent cannot provide or change that filesystem path. `watch_domain` is the
only state-changing MCP tool and stores the same private immutable observation
used by the CLI; all other tools are read-only.

See [docs/agent-interface.md](docs/agent-interface.md) for the complete contract,
[docs/fingerprint-import.md](docs/fingerprint-import.md) for the native
Wappalyzer adapter and compatibility reports,
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
- `internal/probe` fetches homepages, optionally follows a bounded deterministic
  set of same-host pages, and performs exact MX, TXT, and apex CNAME queries.
  HTTPS is preferred; HTTP fallback occurs only for transport/TLS failures.
  DNS uses the system resolver configuration, nameserver failover, UDP first,
  and TCP retry for truncated replies. Local CLI users may opt into literal-IP
  resolvers; MCP always uses the host configuration.
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
- `internal/history` stores private immutable per-domain observations and
  rejects corrupt, oversized, or incompatible history rather than guessing.
- `internal/policy` resolves and pins public addresses for autonomous HTTP
  requests while rejecting private, loopback, link-local, metadata, multicast,
  documentation, and other special-use networks.
- `internal/mcpserver` exposes a small explicitly scoped tool surface using the
  official Go MCP SDK. MCP dependencies and protocol output are isolated in the
  separate `technograph-mcp` executable. Optional history is fixed at process
  startup and cannot be redirected by a tool call.

The supplied fingerprint file uses a normalized representation because the
assignment's header and cookie expressions match names, while native
Wappalyzer normally uses exact names as selectors and applies regexes to their
values. Every rule therefore has an explicit `channel`, `regex`, and optional
`target` (`name` or `value`). A technology is detected when any of its patterns
matches a signal in the same channel. Evidence and technology names are
deduplicated. Optional category metadata is loaded generically from the same
fingerprint definition.

## Accuracy and block handling

Accuracy is intentionally favored over recall:

- only the final response's headers and body are inspected; cookies accepted
  during redirects may contribute when they apply to the final URL;
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

Local CLI users may opt into a resolver with repeatable `--dns-server
IP[:port]` flags (or `-dns-server` in legacy mode). Literal IPv4/IPv6 addresses
are required. Custom resolvers should be treated as parties that can observe
queried domains.

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

`technograph fingerprints import` provides an offline, deterministic adapter
for native upstream technology files. It preserves exact header, cookie, and
meta selectors, resolves category IDs when a mapping is supplied, removes
duplicates, and emits a machine-readable reason for every skipped unsupported
channel or regex. Generated databases remain opt-in; the small reviewed
assignment set stays embedded by default.

The scanner implements static HTTP/DNS channels only. Runtime DOM inspection,
executed JavaScript globals, XHR observation, TLS certificates, robots files,
and unbounded crawling are outside scope. Public pages and DNS records also
change over time, so real results are observations, not permanent facts.

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
an in-memory MCP client/server integration test. Opt-in page coverage tests
also enforce deterministic ordering, deduplication, static-file exclusion,
default compatibility, and cross-host redirect rejection.

## Included real scan

`output.json` is the raw, unedited result of scanning the exact 20 domains in
`domains.txt` on 2026-08-27 (Europe/Sofia) using Go 1.27.0 on Darwin/arm64,
concurrency 10, an 8-second HTTP timeout, and a 3-second per-query DNS timeout.
The final measured wall time was 4.064 seconds. All 20 domains were emitted; there
were zero HTTP transport failures and one detected challenge response.
