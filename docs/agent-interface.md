# Agent interface

Technograph v0.2 adds a versioned machine interface without changing the
original assignment command. The legacy invocation remains:

```console
technograph -output output.json domains.txt
```

## Structured CLI

Scan direct arguments, stdin, or a file:

```console
technograph scan stripe.com shopify.com --format json
technograph explain stripe.com shopify.com
technograph explore stripe.com shopify.com
technograph explain stripe.com --pages 3
technograph scan stripe.com shopify.com --format table
technograph scan --input domains.txt --format csv --output results.csv
printf 'stripe.com\nshopify.com\n' | technograph scan --format jsonl
technograph scan --input domains.txt --output snapshot.json
```

`technograph explain` runs the same scanner and presents its typed status,
technology evidence, HTTP/DNS coverage, and issues as deterministic plain text.
It is intended for terminal exploration and live reviews; automation should
continue to consume the versioned JSON or JSONL interfaces. Table is a bounded
terminal overview. CSV emits one input-ordered row per domain and guards cells
against spreadsheet formula injection.

Flags may appear before or after domains. JSON is written to stdout by default;
all logs and warnings use stderr. `--output -` also means stdout. JSONL emits a
`scan_started` record, one `domain_result` record per input in completion order,
and a final `scan_completed` record.

Each domain has one status:

- `ok`: HTTP and DNS collection completed without recorded errors.
- `partial`: at least one source failed but other evidence may be usable.
- `blocked`: the homepage returned a soft block or challenge; DNS and safe
  response metadata may still produce detections.
- `failed`: HTTP and all three DNS record queries failed.
- `invalid`: the input was rejected before network access.

The command exits nonzero for request-level failures such as unreadable files,
invalid configuration, or output errors. Per-domain failures are represented in
JSON and do not make a successfully executed batch fail.

The stable schema is `1.0`; see `schemas/scan-report.schema.json`. A
fingerprint's confidence directive is included only in its matching evidence.
Technograph deliberately does not invent a combined technology confidence
score.

When available, `technology_categories` maps detected technology names to
descriptive categories. This metadata cannot cause a detection. The same data
appears in fingerprint inventory responses, table output, CSV, and human
evidence reports.

For a human-led terminal review, `technograph explore` scans once and accepts
`list`, `filter TEXT`, `clear`, `show NUMBER|DOMAIN`, `help`, and `quit`. It
reuses the structured scan and deterministic explanation renderer; it is not a
dashboard and does not start a server. Automation and agents should continue
to use JSON/JSONL or MCP rather than scripting the interactive prompt.

### Optional bounded page coverage

`scan`, `explain`, and `watch` accept `--pages 1-5`. The default is `1`, so the
original homepage-only behavior and output remain unchanged. Higher values
follow a deterministic priority order for same-host links such as pricing,
integrations, features, products, solutions, customers, about, and contact.

Queries and fragments are removed for deduplication. Static-file extensions,
credentials, non-HTTP schemes, nonstandard ports, external hosts, and
cross-host redirects are rejected. All pages share the normal per-domain HTTP
deadline. Secondary blocks and failures are typed as `http_page` issues and
make an otherwise complete result `partial`; usable evidence is retained.
The MCP server deliberately remains homepage-only to keep autonomous request
cost and reach fixed.

## Validation and fingerprint discovery

```console
technograph validate example.com https://invalid.example
technograph fingerprints
technograph fingerprints import --input webappanalyzer/src/technologies --output generated.json --report compatibility.json
```

Validation performs no network access. Fingerprint discovery reports the exact
embedded rules used by the binary. A local structured CLI invocation may load
an external normalized database with `--fingerprints`; the MCP server cannot.
The offline `fingerprints import` adapter can generate that normalized database
from native Wappalyzer files, but generated data remains local and is never
accepted through MCP.

## Snapshots and conservative diffs

Any JSON scan report is a snapshot:

```console
technograph scan --input domains.txt --output before.json
# run again later
technograph scan --input domains.txt --output after.json
technograph compare before.json after.json --output diff.json
```

Additions are reported whenever newly observed. Removals are reported only when
the current domain status is `ok`. If the current request was blocked, partial,
failed, or missing, possible removals go into `uncertain` instead. This prevents
a temporary outage or bot challenge from becoming a false "technology
removed" alert. The diff schema is in `schemas/diff-report.schema.json`.

## One-shot local watch history

For local scheduler workflows, `watch` performs the scan, comparison, and
immutable save in one bounded invocation:

```console
technograph watch --input domains.txt --store /absolute/history --output watch.json
technograph history stripe.com --store /absolute/history --limit 10
```

First observations and scanner/fingerprint identity changes are returned as
baselines, not additions/removals. Page-limit changes are included in the
scanner compatibility identity. `--fail-on-change` returns status 3 only for
confirmed changes and only after the JSON report and history are written.
Uncertain removals remain data, not a notification exit. The schemas are
`schemas/watch-report.schema.json` and `schemas/history-report.schema.json`.

## Local MCP server

`technograph-mcp` is a separate stdio binary so MCP protocol JSON can never be
mixed with normal CLI output. It always exposes five tools:

- `scan_domain`
- `scan_domains` (maximum 20 domains)
- `explain_domain` (deterministic evidence-grouped claims)
- `validate_domain`
- `list_fingerprints`

Example client configuration:

```json
{
  "mcpServers": {
    "technograph": {
      "command": "technograph-mcp"
    }
  }
}
```

History is explicitly opt-in at process startup:

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

This adds `watch_domain` and `domain_history`. The former performs a fresh scan,
conservative comparison, and immutable save; the latter is offline and
read-only. Tool inputs never contain a path, so an agent cannot redirect the
store. MCP history operations use homepage-only coverage and the same
scanner/fingerprint compatibility baselines as CLI `watch`.

The server uses only embedded fingerprints, enforces a global 20-domain work
limit, and always enables its autonomous network policy. It accepts bare public
domains only, resolves targets before dialing, rejects private/loopback/link-
local/reserved addresses, pins the validated IP for the connection, validates
every redirect through the same dial policy, limits ports to 80/443, and ignores
proxy environment variables. These controls also protect against common DNS
rebinding paths. Host headers and TLS SNI retain the original public hostname.

Autonomous scans are intended for public domains. Names under reserved or
unmanaged suffixes (for example `service.internal`) currently parse as bare
domains and rely on the network policy: HTTP connections to private addresses
are blocked, but DNS queries for those names are still sent to the configured
resolver (system or `--dns-server`). Until a strict public-suffix policy is
adopted, internal-domain scans should not be used where DNS disclosure is a
concern.

The structured CLI applies the same network policy by default. Its explicit
`--allow-private-network` option exists only for trusted local testing and is
not available through MCP.

For local operational testing, `scan` and `explain` accept repeatable
`--dns-server IP[:port]` options. Literal resolver IP addresses are required;
omitting the port uses 53. The setting is intentionally absent from MCP so an
agent cannot redirect DNS traffic or silently change the scanner's trust
boundary.

Technograph v0.2 intentionally ships local stdio MCP only. A public remote MCP
service would require authentication, tenant isolation, quotas, rate limits,
durable storage, and operational monitoring; wrapping this binary in an
unauthenticated HTTP endpoint would not be safe.
