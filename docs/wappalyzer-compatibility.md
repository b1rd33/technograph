# Wappalyzer Compatibility Note

Date checked: 2026-08-27

## Scope

This note defines what the project means by “Wappalyzer-style fingerprints.”
It is based on the current open-source WebAppAnalyzer specification, schema,
and technology corpus maintained by Enthec.

Primary references:

- https://github.com/enthec/webappanalyzer
- https://github.com/enthec/webappanalyzer/blob/main/schema.json
- https://github.com/enthec/webappanalyzer/tree/main/src/technologies

## Native Wappalyzer shapes

The upstream database is a technology-name-to-object mapping. Pattern-bearing
fields have different structures:

- `scriptSrc`, `scripts`, `html`, `text`, `css`, `robots`, `url`, and `xhr`
  contain lists of pattern strings.
- `headers` maps an exact header name to a pattern applied to its value.
- `cookies` maps an exact cookie name to a pattern applied to its value.
- `meta` maps a meta name/property to one or more content patterns.
- `js` maps a JavaScript property path to a value pattern.
- `dns` maps a DNS record type such as `MX` to pattern lists.

The assignment's supplied table is a normalized subset rather than a complete
native technology object. In particular, its `header` and `cookie` patterns are
patterns for names, whereas native Wappalyzer header/cookie maps normally use
exact names as selectors and apply their patterns to values.

The project will therefore use a normalized internal representation that can
express both forms structurally: channel, name selector or name pattern, value
pattern, source expression, confidence, and optional version template.

## Pattern-string behavior

The upstream specification states that:

- Pattern strings use JavaScript regular-expression syntax.
- Patterns are case-insensitive; inline flags are not part of the data format.
- Extra tags are appended using `\;tag:value`.
- `confidence` defaults to 100.
- `version` can refer to capture groups and supports Wappalyzer's conditional
  replacement syntax.

The assignment's 24 supplied patterns contain no confidence or version tags,
so detection behavior for the required submission is not affected by version
template support. The loader will still parse and retain supported tags so the
matcher is data-driven and extensible.

## Go RE2 experiment

The Phase 0 probe compiled patterns case-insensitively with Go's standard
`regexp` package after removing Wappalyzer metadata tags.

Results:

- Assignment patterns: 24 total, 24 compiled, 0 failed.
- Current upstream patterns in pattern-bearing fields: 13,724 total.
- Compiled with Go RE2: 13,710.
- Rejected by Go RE2: 14.
- Compatibility for the measured corpus: 99.90%.

All 14 rejected patterns use JavaScript lookahead or lookbehind. Examples occur
in Vue.js, AngularJS, WooCommerce, Leaflet, jQuery, UPS, and several other
technologies. Go RE2 intentionally does not support those constructs.

The corpus count covers the upstream pattern-bearing fields listed above,
including DNS and certificate-issuer patterns. DOM selector/probe structures
were not counted as regex patterns because they have separate semantics and are
outside this HTTP-only assignment's required matcher.

The measurement was performed with a temporary probe during Phase 0; neither
that scratch program nor the upstream corpus is included in the submission.

## Decision

Use Go's standard `regexp` engine for the submission.

Reasons:

1. Every required assignment pattern is supported.
2. RE2 provides linear-time matching and avoids regex backtracking risks.
3. Adding a .NET-style backtracking engine would still not guarantee exact
   JavaScript-regex behavior.
4. The measured compatibility benefit of another engine is too small to justify
   the added complexity for this take-home.

The fingerprint package will keep regex compilation behind a small internal
abstraction. Bundled pattern compilation failures are fatal at startup.
Unsupported patterns in an optional external database will be reported with
technology/channel context; they will never be silently translated into a
different regex because that could create false detections.

## Compatibility statement for README

Use the following wording, or a concise equivalent:

> Technograph implements its own data-driven matcher for the supplied
> fingerprint set and supports Wappalyzer-style case-insensitive regex strings,
> including confidence and version metadata parsing. It does not use Wappalyzer
> as a dependency. Go's RE2 engine supports all supplied patterns and 99.90% of
> the current upstream patterns measured in the supported pattern-bearing
> fields; unsupported JavaScript lookaround patterns are reported rather than
> rewritten. Runtime DOM and JavaScript-value detection are outside this
> static, HTTP-only scanner's scope.
