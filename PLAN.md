# Technographic Detection CLI — Implementation Plan

## Objective

Build a minimal, production-quality Go CLI that accepts a text file containing
one company domain per line and writes a JSON mapping from each domain to the
technologies detected from public HTTP, HTML, cookie, and DNS signals.

The implementation must be conservative: a technology is reported only when a
supplied fingerprint matches an observed signal. HTTP failures and soft blocks
must reduce coverage without producing invented detections or aborting the
complete scan.

## Chosen implementation

- Language: Go (final decision)
- HTTP: `net/http`
- HTML parsing: `golang.org/x/net/html`
- Domain normalization: `golang.org/x/net/idna` and
  `golang.org/x/net/publicsuffix`
- DNS: `github.com/miekg/dns`
- Default regex engine: Go `regexp` (RE2)
- Logging: `log/slog`
- CLI parsing: standard `flag` package
- JSON: `encoding/json` with a deterministic custom writer
- Bundled data: `go:embed`

No browser, JavaScript execution, paid API, proxy network, CAPTCHA solver, or
Cloudflare bypass will be used.

### Why Go

The assignment permits Python libraries but does not require Python. Go is the
final choice because this deliverable is a bounded concurrent CLI: goroutines,
contexts, a reusable HTTP transport, race-detector verification, and a single
distributable binary fit that shape well. The README will explain this choice
briefly and will not imply that Go was required by the assignment.

The main tradeoff is regex compatibility. Go's RE2 engine is intentionally more
limited than JavaScript regexes, so Phase 0 must measure and document the
boundary before the implementation makes any compatibility claim. The language
will remain Go regardless; only the internal regex adapter may change if the
evidence justifies it.

## Fixed behavioral decisions

1. A technology is detected when any one of its fingerprints matches.
2. Header fingerprints in the assignment match header names.
3. Cookie fingerprints in the assignment match cookie names.
4. Script fingerprints match script `src` URLs and inline script source text.
5. Raw HTML patterns match only a genuine final response body.
6. Confirmed challenge pages contribute headers, relevant cookies, and DNS, but
   not HTML, scripts, meta tags, or JavaScript-global signals.
7. Intermediate redirect infrastructure does not contribute detections.
8. DNS queries run even if HTTP fails or is blocked.
9. Every valid input domain appears in `output.json`, using `[]` when nothing
   can be detected.
10. Technologies are deduplicated and sorted.
11. Errors and diagnostics go to stderr, never into the required JSON file.
12. The README will describe actual compatibility and limitations without
    claiming that the upstream Wappalyzer database is a drop-in dependency.
13. Accuracy is more important than detection count. An empty technology list
    is correct when the scanner has no matching evidence.
14. The scanner never assumes that a vendor's own domain uses that vendor's
    technology.
15. Fingerprints use OR semantics: one matching pattern detects the technology;
    additional matches add evidence but not duplicate output entries.
16. The script channel includes both `src` values and inline script source, which
    is required for patterns such as `gtag\(`.
17. Public pages and DNS records change. The committed output is a timestamped,
    measured snapshot, not an expected evergreen answer key.

## Scope discipline

“Production-quality” means bounded network behavior, conservative attribution,
clear errors, deterministic output, tests, and auditable matches. It does not
mean building a platform around the assignment.

Required work is completed before optional enhancements. The optional evidence
report and static `window.*` extraction may be added only after the core CLI,
required channels, tests, and live output are complete. Caching, persistence,
distributed workers, dashboards, plugin systems, and multi-page crawling are
outside the submission scope.

## Target repository layout

```text
.
├── cmd/technograph/
│   └── main.go
├── internal/
│   ├── cli/
│   ├── model/
│   ├── fingerprint/
│   ├── extract/
│   ├── probe/
│   ├── scanner/
│   └── output/
├── testdata/
├── fingerprints.json
├── domains.txt
├── output.json
├── go.mod
├── go.sum
├── Makefile
├── README.md
└── PLAN.md
```

## Phase 0 — Wappalyzer compatibility spike

### Goal

Define an honest and testable compatibility boundary before designing the
fingerprint loader.

### Tasks

- Inspect representative entries from the open-source Wappalyzer technology
  database.
- Document the native shapes used for HTML, script, headers, cookies, meta, and
  JavaScript patterns.
- Examine Wappalyzer pattern directives such as `confidence` and `version`.
- Compile a representative sample with Go's standard `regexp` package.
- Record which JavaScript-regex constructs RE2 rejects, such as lookarounds or
  backreferences.
- Keep regex compilation behind a small internal interface so the engine can be
  replaced later without changing scanning logic.
- Use a more permissive regex engine only if the measured compatibility benefit
  justifies its backtracking and timeout complexity.

### Deliverable

A short compatibility note in the README and tests covering every supported
pattern directive.

### Completion gate

The project can state precisely what “Wappalyzer-style” means and does not make
an unsupported full-database compatibility claim.

## Phase 1 — Project foundation

### Goal

Create a clean, buildable Go module with stable package boundaries.

### Tasks

- Initialize `go.mod`.
- Create the repository layout.
- Add the exact 20 test domains to `domains.txt` (`webflow.com`, without the
  formatting escape shown in the assignment).
- Add the exact 24 supplied fingerprints to `fingerprints.json`.
- Embed the default fingerprint file with `go:embed` while retaining the JSON
  file in the repository for transparency.
- Add a Makefile with formatting, testing, race testing, vetting, building, and
  scanning commands.
- Add `.gitignore` for build and editor artifacts.

### Tests

- The module builds.
- The embedded fingerprint data loads.
- The dataset contains 16 technologies and 24 patterns.

### Completion gate

`go build ./cmd/technograph` succeeds with a placeholder command, and the exact
assignment fixtures are versioned.

## Phase 2 — Domain and input handling

### Goal

Turn the domains file into a safe, deterministic list of normalized company
domains and DNS apexes.

### Tasks

- Read one domain per line.
- Ignore blank lines and full-line comments.
- Normalize Unicode hostnames to IDNA ASCII.
- Lowercase DNS hostnames and remove trailing dots.
- Reject schemes, paths, query strings, fragments, ports, IP literals, empty
  labels, and malformed hostnames.
- Use the Public Suffix List to derive the effective top-level domain plus one.
- Preserve the normalized submitted hostname as the JSON key and keep the
  derived apex separately for DNS.
- Deduplicate entries while preserving their first input position.
- Include file name and line number in invalid-input errors.

### Tests

- Ordinary apex domains.
- Mixed case and trailing dots.
- Internationalized domains.
- `www.example.co.uk` produces apex `example.co.uk`.
- Invalid paths, ports, IPs, and malformed labels.
- Duplicate and commented lines.
- Fuzz test for the domain parser.

### Completion gate

Input behavior is deterministic, line-numbered errors are actionable, and no
network work begins for an invalid input file.

## Phase 3 — Signal and evidence model

### Goal

Represent observations structurally so matching remains accurate and can grow
without redesigning the probes.

### Tasks

- Define channel constants for header, cookie, script, HTML, meta, JS, DNS MX,
  DNS TXT, and DNS CNAME.
- Represent header and cookie names separately from their values.
- Preserve signal origin (final response, script source, inline script, DNS
  record type, etc.).
- Define a compiled fingerprint containing technology, channel, expression,
  target part, confidence, and optional version template.
- Define evidence containing the technology, channel, source pattern, matched
  text, and signal origin.
- Preserve original case for HTML, JavaScript, paths, cookie values, and header
  values; normalize only channels whose protocol semantics require it.

### Tests

- Header names and values cannot be confused.
- Cookie names and values cannot be confused.
- Channel isolation prevents a string observed in HTML from satisfying a DNS
  pattern.

### Completion gate

The scanner can collect richer structured signals while the required output
remains a list of technology names.

## Phase 4 — Fingerprint loader and matcher

### Goal

Implement generic, data-driven detection with no technology-specific Go code.

### Tasks

- Load embedded fingerprints by default.
- Support an optional external fingerprint file.
- Accept one pattern or a list of patterns per channel.
- Parse supported Wappalyzer directives.
- Compile all patterns once at startup.
- Fail clearly for malformed bundled fingerprints.
- Report unsupported external patterns with technology and channel context.
- Index patterns by channel.
- Apply the correct default target: assignment headers and cookies target names.
- Deduplicate evidence per technology/channel/pattern.
- Produce sorted technology names.

### Tests

- Positive test for all 24 required patterns.
- Negative test for each channel family.
- `cf-ray` in a header value does not detect Cloudflare.
- Header names match case-insensitively.
- Cookie-name prefix matching works.
- Multiple HubSpot or Cloudflare rules produce one technology name.
- Pattern compile failure occurs before any scan begins.
- Directive parsing handles escapes and semicolons.
- Unsupported-regex behavior is explicit.
- Fuzz test for directive parsing.

### Completion gate

The complete supplied fingerprint set passes offline tests, and adding another
technology requires only data changes.

## Phase 5 — Static document extraction

### Goal

Extract strong HTTP-visible signals without executing JavaScript.

### Tasks

- Parse HTML using `x/net/html`.
- Retain a capped raw HTML signal.
- Extract script `src` attributes in their raw form and resolved absolute form.
- Extract bounded inline script text.
- Treat inline script source as part of the `script` channel so `gtag\(` and
  similar fingerprints can match without JavaScript execution.
- Extract meta name/property/http-equiv and content structurally.
- Extract cookie names and values from parsed response cookies.
- Optionally extract syntactic `window.foo` and `window["foo"]` references only
  after the required channels are complete.
- Never evaluate code or infer runtime JavaScript values.

### Tests

- Absolute, relative, and protocol-relative script URLs.
- Inline `gtag(` detection.
- Meta name/value extraction.
- Malformed HTML does not crash extraction.
- Large inline scripts are bounded.
- Static globals, if implemented, are described and tested as syntax only.

### Completion gate

At least six strong signal groups are extracted correctly using offline HTML
fixtures.

## Phase 6 — HTTP probe and soft-block policy

### Goal

Fetch the intended homepage safely while attributing only final-site evidence.

### Tasks

- Reuse a configured `http.Client` and transport.
- Request HTTPS first.
- Fall back to HTTP only after transport or TLS failure.
- Do not fall back for HTTP response statuses.
- Follow redirects with a hard maximum.
- Keep redirect history for diagnostics but do not match its headers or bodies.
- Use a cookie jar so only cookies applicable to the final host are considered.
- Enable TLS verification by default and offer an explicit `-insecure` option.
- Configure connect, TLS handshake, response-header, idle, and overall request
  deadlines.
- Limit the decompressed body with `io.LimitReader(max+1)` and record truncation.
- Allow Go's HTTP transport to decode supported content encodings, then enforce
  the size limit on the decoded stream so compressed responses cannot expand
  without a bound.
- Parse a response as HTML when its media type is `text/html` or
  `application/xhtml+xml`. For missing or incorrect content types, use a small,
  conservative HTML-sniffing fallback instead of parsing arbitrary binary data.
- Close the body on every path.
- Classify challenges using status, headers, and recognizable body markers.
- Treat a plain 403 as denied, not automatically as a confirmed Cloudflare
  challenge.
- Suppress challenge-page HTML-derived signals.

### Tests

- Normal 200 response.
- Redirect to a final host.
- Redirect-provider headers do not trigger detection.
- Applicable redirect cookies are retained; unrelated cookies are not.
- HTTPS transport failure triggers HTTP fallback.
- 403, 404, 429, and 5xx statuses do not trigger HTTP fallback.
- Confirmed challenge scripts are excluded.
- Plain 403 classification remains conservative.
- Oversized and non-UTF-8 bodies.
- Compressed responses are limited after decompression.
- Correct, missing, misleading, and non-HTML content types.
- Redirect loop and timeout.
- Every response body is closed.

### Completion gate

The HTTP probe is bounded, conservative, and returns useful partial evidence
for blocked responses without attempting a bypass.

## Phase 7 — DNS probe

### Goal

Collect exact MX, TXT, and apex CNAME RRsets with bounded and isolated errors.

### Tasks

- Read the system resolver configuration.
- Query the derived apex as an FQDN.
- Query MX, TXT, and CNAME concurrently.
- Try configured nameservers with failover.
- Use UDP first and retry the same query over TCP when the truncated flag is
  present.
- Apply an individual deadline to every DNS query.
- Extract exact answer RRsets rather than relying on canonical-name resolution.
- Normalize MX exchanges without preferences or trailing dots.
- Join fragments belonging to the same TXT RR while preserving separate RRs.
- Normalize CNAME targets by removing trailing dots.
- Deduplicate records.
- Distinguish NXDOMAIN, NODATA, timeout, and resolver failure internally.
- Treat an empty apex CNAME response as normal.

### Tests

- MX, TXT, and CNAME normalization.
- Multi-fragment and multiple TXT records.
- NODATA versus NXDOMAIN.
- One record-type failure does not hide the other results.
- Nameserver failover.
- UDP truncation retries over TCP.
- Query cancellation and deadline.

### Completion gate

DNS produces normalized signals independently of HTTP and cannot hold a domain
worker beyond its deadline.

## Phase 8 — Concurrent scanner

### Goal

Scan all domains quickly with hard resource and time bounds.

### Tasks

- Create a bounded worker pool, defaulting to 10 domain workers.
- Give every domain one parent context deadline of approximately 10–12 seconds.
- Run HTTP and DNS concurrently within the domain context.
- Run the DNS record types concurrently.
- Contain per-probe failures and panics as domain diagnostics.
- Preserve input order in the result collection.
- Include every valid domain even on total failure.
- Consider a 55-second whole-scan deadline as a final safety boundary.
- Ensure cancellation does not leak goroutines.

### Tests

- Worker concurrency never exceeds the configured limit.
- HTTP and DNS overlap rather than running sequentially.
- Domain deadline cancels slow children.
- One broken domain does not affect other domains.
- Cancellation leaves no blocked goroutines.
- Results preserve input order.

### Completion gate

Offline timing tests prove bounded concurrency, and the scanner has a genuine
upper time bound compatible with the 60-second requirement.

## Phase 9 — CLI and required JSON output

### Goal

Provide a small, predictable command that produces exactly the submission
format.

### Proposed command

With the standard Go flag parser, flags precede the positional file:

```bash
technograph -output output.json -concurrency 10 domains.txt
```

### Proposed flags

- `-output`
- `-concurrency`
- `-timeout`
- `-dns-timeout`
- `-fingerprints`
- `-report` for an optional evidence sidecar
- `-insecure`
- `-verbose`

### Tasks

- Keep `output.json` exactly as `{ "domain": ["Technology"] }`.
- Use a deterministic custom JSON writer that follows input domain order.
- Sort each technology list.
- Write through a temporary file and atomically rename it.
- Send all logs and summaries to stderr.
- Return nonzero for invalid input, invalid fingerprints, or an unwritable
  output path.
- Do not return nonzero merely because individual sites are blocked or
  unreachable.
- Keep evidence, timings, statuses, and errors out of the required output.

### Tests

- Golden test for the exact JSON schema and formatting.
- Deterministic repeated writes.
- Atomic-write failure behavior.
- Empty detections serialize as `[]`, not `null`.
- Individual scan failures still produce a successful completed CLI run.
- Invalid CLI inputs produce useful errors and a nonzero exit code.

### Completion gate

The command can run end-to-end against fully mocked HTTP and DNS and produces
byte-stable required JSON.

## Phase 10 — Verification and quality pass

### Goal

Demonstrate correctness before using changing public websites.

### Commands

```bash
go fmt ./...
go vet ./...
go test ./...
go test -race ./...
go build ./cmd/technograph
```

### Additional checks

- Inspect dependency licenses and keep the dependency set small.
- Review all context cancellation and body-closing paths.
- Review all matches for false-positive attribution risks.
- Ensure no secret, local path, debug dump, or generated binary is committed.
- Test installation and execution from a clean directory.

### Completion gate

Formatting, tests, race tests, vetting, and the production build all pass.

## Phase 11 — Live scan and detection audit

### Goal

Generate the real submission output and prove the performance requirement.

### Tasks

- Build the release binary.
- Run the exact 20-domain fixture.
- Measure wall-clock duration on the current laptop.
- Record the scan timestamp, Go version, operating system/architecture,
  configured concurrency, and timeout values.
- Save the unedited required `output.json`.
- Use the optional evidence report to audit every detection.
- Investigate suspicious detections by examining the recorded signal and
  pattern, not by adding domain-specific rules.
- Record soft blocks and unreachable domains in the README without changing
  the required JSON schema.
- Record the number of successful HTTP responses, soft blocks, HTTP failures,
  and total detections alongside the benchmark.
- Repeat the scan to understand normal result variability.

### Completion gate

- All 20 domains appear in `output.json`.
- Every reported technology has matching evidence.
- The scan completes in under 60 seconds.
- `output.json` is from an actual run, not a simulation or hand-edited example.

## Phase 12 — README and repository handoff

### Goal

Make the repository easy to install, evaluate, and discuss in an interview.

### README contents

- Problem summary and constraints.
- Prerequisites and installation.
- Build and run commands.
- Input and output examples.
- Architecture overview.
- Signal-channel table.
- Fingerprint format and matching semantics.
- Wappalyzer compatibility boundary.
- Redirect attribution and soft-block decisions.
- Concurrency and timeout design.
- Test and verification commands.
- Actual measured scan duration.
- Scan timestamp, environment, concurrency, timeout configuration, and counts of
  soft blocks and unreachable domains.
- A note that live websites and DNS change, so later reruns can differ from the
  committed raw output.
- Known limitations and false-negative sources.

### Repository checks

- Source code is complete.
- `domains.txt` contains exactly the required domains.
- `output.json` is the real scan output.
- No generated binary is committed.
- No simulated claims remain.
- Git status is clean after the final commit.

### Completion gate

The repository satisfies every submission requirement and can be evaluated from
the README without additional instructions.

## Acceptance checklist

- [ ] Plain-text domain input
- [ ] Redirects and timeouts handled
- [ ] Conservative soft-block handling
- [ ] At least four signal channels implemented
- [ ] Exact supplied fingerprint set
- [ ] Generic data-driven matcher
- [ ] Wappalyzer-style directives supported within documented boundaries
- [ ] No headless browser
- [ ] No paid API
- [ ] Stable required JSON output
- [ ] All 20 domains included
- [ ] Real scan under 60 seconds
- [ ] Unit, integration, race, and static checks pass
- [ ] README contains install, run, architecture, limitations, and measurement
- [ ] Actual `output.json` committed

## Deliberate non-goals

- Executing JavaScript
- Rendering pages
- Circumventing bot protection
- Using DNS-over-HTTPS as an external fallback
- Crawling paths beyond the homepage
- Domain-specific detection exceptions
- Retrying response statuses aggressively
- Claiming runtime JavaScript-global detection from source text
- Claiming the upstream Wappalyzer database is directly supported without an
  adapter and compatibility evidence
- Adding a detection because the target domain belongs to that technology's
  vendor
- Editing live output to make it look more complete
- Optimizing for the number of detections at the expense of evidence quality
