# Native Wappalyzer fingerprint import

Technograph includes an offline adapter for native open-source Wappalyzer
technology JSON. The upstream database is not bundled and is not a runtime
dependency. Download and license the corpus separately, then run:

```console
technograph fingerprints import \
  --input webappanalyzer/src/technologies \
  --categories webappanalyzer/src/categories.json \
  --output fingerprints.generated.json \
  --report compatibility.json
```

The generated database can be inspected and used immediately:

```console
technograph fingerprints --fingerprints fingerprints.generated.json
technograph scan stripe.com --fingerprints fingerprints.generated.json
```

Use repeatable `--technology` flags for a curated external set. Matching is
exact and case-sensitive at selection time:

```console
technograph fingerprints import \
  --input webappanalyzer/src/technologies \
  --categories webappanalyzer/src/categories.json \
  --technology Stripe \
  --technology Shopify \
  --output commerce-fingerprints.json \
  --report commerce-compatibility.json
```

## Conversion boundary

The adapter imports only signals with equivalent static HTTP/DNS semantics:

| Native field | Normalized channel |
| --- | --- |
| `scriptSrc`, `scripts` | `script` |
| `html` | `html` |
| `headers` | `header` with exact name selector |
| `cookies` | `cookie` with exact name selector |
| `meta` | `meta` with exact name/property selector |
| `dns.MX`, `dns.TXT`, `dns.CNAME` | matching apex DNS channel |

`text`, `css`, `robots`, `url`, `xhr`, runtime `js`, `dom`, certificate
issuer patterns, and uncollected DNS types are skipped and reported. Their
semantics are not approximated because doing so could introduce false
positives. Empty native header/cookie/meta patterns retain presence semantics
through their exact selector. Imported `scriptSrc` and `scripts` rules are also
scoped to external-script and inline-script signal origins respectively, so a
URL pattern appearing merely as inline source text cannot create a match.

Every pattern is parsed for Wappalyzer tags and compiled with Go RE2 before it
is emitted. Unsupported JavaScript regex constructs are listed individually in
the compatibility report. Identical normalized rules are deduplicated and
reported. `--strict` exits nonzero and withholds the generated database if any
pattern would be skipped; when `--report` is provided, the report is still
written for diagnosis.

Imports are deterministic, limited to 64 MiB per source file and 256 MiB per
corpus, and do not follow symlinks recursively or make network requests. A
directory import reads only its immediate `.json` files in sorted order.

## Measured full-corpus check

On 2026-08-28, native corpus commit
`b0e1186877307b246769bdeab61f270b597f6886` produced:

- 7,596 technologies inspected;
- 5,862 technologies with at least one equivalent static pattern;
- 7,665 imported patterns across eight normalized channels;
- 7,756 explicitly skipped unsupported-channel entries;
- 6 duplicate normalized patterns removed;
- 13 unsupported JavaScript regexes reported;
- zero unresolved categories when `src/categories.json` was supplied.

The import took 0.17 seconds and two independent imports produced identical
SHA-256 digests. The generated database loaded in 65 ms. A live scan of the
assignment's 20 domains with all 7,665 patterns completed in 14.6 seconds; the
bundled 24-pattern assignment database remains the default and completed the
same check in about 3 seconds. Live web timings and detections naturally vary.

The normalized database and report contracts are described by
`schemas/fingerprint-database.schema.json` and
`schemas/import-report.schema.json`.
