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
printf 'stripe.com\nshopify.com\n' | technograph scan --format jsonl
technograph scan --input domains.txt --output snapshot.json
```

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

## Validation and fingerprint discovery

```console
technograph validate example.com https://invalid.example
technograph fingerprints
```

Validation performs no network access. Fingerprint discovery reports the exact
embedded rules used by the binary. A local structured CLI invocation may load
an external normalized database with `--fingerprints`; the MCP server cannot.

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

## Local MCP server

`technograph-mcp` is a separate stdio binary so MCP protocol JSON can never be
mixed with normal CLI output. It exposes four read-only tools:

- `scan_domain`
- `scan_domains` (maximum 20 domains)
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

The server uses only embedded fingerprints, enforces a global 20-domain work
limit, and always enables its autonomous network policy. It accepts bare public
domains only, resolves targets before dialing, rejects private/loopback/link-
local/reserved addresses, pins the validated IP for the connection, validates
every redirect through the same dial policy, limits ports to 80/443, and ignores
proxy environment variables. These controls also protect against common DNS
rebinding paths. Host headers and TLS SNI retain the original public hostname.

The structured CLI applies the same network policy by default. Its explicit
`--allow-private-network` option exists only for trusted local testing and is
not available through MCP.

Technograph v0.2 intentionally ships local stdio MCP only. A public remote MCP
service would require authentication, tenant isolation, quotas, rate limits,
durable storage, and operational monitoring; wrapping this binary in an
unauthenticated HTTP endpoint would not be safe.
