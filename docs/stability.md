# Stability and compatibility

Technograph 1.x follows semantic versioning for its supported user-facing
interfaces. A patch release fixes behavior without intentionally changing a
contract. A minor release may add optional fields, commands, flags, status or
issue values, fingerprints, and MCP tools. Removing or changing an existing
contract requires a new major version.

## Stable interfaces

- The original `technograph [legacy flags] domains.txt` command and its
  `{ "domain": ["Technology"] }` output remain compatible with the assignment.
  The immutable original submission is tagged `v0.1.0`.
- Structured `scan` JSON, JSONL event envelopes, `compare`, `watch`, `history`,
  fingerprint import, and evidence explanation use schema version `1.0`.
  Published schemas live in `schemas/`.
- Existing CLI command names, flags, and meanings remain compatible throughout
  1.x. New optional flags may be added.
- Existing MCP tool names, input fields, and structured result fields remain
  compatible throughout 1.x. New optional tools or fields may be added.
- Normalized fingerprint database schema version `1` remains loadable
  throughout Technograph 1.x.

JSON consumers must ignore unknown object fields and issue codes. Arrays whose
order is documented as deterministic remain ordered; callers must not infer
meaning from ordering where none is documented. Technology/category names and
fingerprint inventory can grow as reviewed fingerprint data changes.

## Exit statuses

| Status | Meaning |
| --- | --- |
| `0` | The requested command completed; per-domain problems are represented in output. |
| `1` | A request-level I/O, configuration, fingerprint, storage, or execution failure occurred. |
| `2` | Command usage or flag validation failed. |
| `3` | `watch --fail-on-change` wrote its output/history and found confirmed changes. |

## Explicit non-guarantees

Public websites, DNS, bot protection, redirects, and fingerprint databases
change independently of Technograph. A successful scan is a timestamped
observation, not a guarantee that all software was discovered. Detection count,
specific live results, latency, and whether a site blocks HTTP clients are not
API compatibility promises.

Technograph does not guarantee browser-equivalent visibility, JavaScript
execution, block bypassing, or support for private network targets in
autonomous interfaces. It deliberately prefers an explained false negative to
an unsupported positive claim.

## Go source compatibility

The supported products are the binaries, schemas, and MCP contracts. Packages
under `internal/` are implementation details. The root Go package exposes the
embedded reviewed fingerprint data but is not intended as a full scanner SDK.
