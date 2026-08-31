<!-- Generated from fingerprints.json — do not edit by hand. Run `make fingerprints-doc` to regenerate. -->
# Fingerprints

Source: `fingerprints.json` (`schema_version: 1`) — 16 technologies, 24 patterns.

This document is generated from the bundled normalized fingerprint database via `fingerprint.Load(strict=true) → Descriptors()`. It is the single source of truth for offline inspection. See `technograph fingerprints --help` for live inspection.

| Technology | Channel | Target | Selector | Origins | Pattern | Confidence | Categories |
|---|---|---|---|---|---|---|---|
| Cloudflare | header | name |  |  | `cf-cache-status` | 100 | CDN |
| Cloudflare | header | name |  |  | `cf-ray` | 100 | CDN |
| Drift | script | value |  |  | `js\\.driftt\\.com` | 100 | Conversational marketing |
| Google Analytics 4 | script | value |  |  | `google-analytics\\.com/g/collect` | 100 | Analytics |
| Google Analytics 4 | script | value |  |  | `gtag\\(` | 100 | Analytics |
| Google Workspace | dns_mx | value |  |  | `google\\.com` | 100 | Email |
| Hotjar | script | value |  |  | `static\\.hotjar\\.com` | 100 | Analytics |
| HubSpot | dns_txt | value |  |  | `hubspot-developer-verification` | 100 | Marketing automation |
| HubSpot | script | value |  |  | `//js\\.hs-scripts\\.com/` | 100 | Marketing automation |
| HubSpot | script | value |  |  | `//js\\.hsforms\\.net/` | 100 | Marketing automation |
| Intercom | cookie | name |  |  | `^intercom-` | 100 | Customer support |
| Intercom | script | value |  |  | `widget\\.intercom\\.io/` | 100 | Customer support |
| Microsoft 365 | dns_mx | value |  |  | `protection\\.outlook\\.com` | 100 | Email |
| Salesforce | dns_cname | value |  |  | `\\.salesforce\\.com` | 100 | CRM |
| Segment | script | value |  |  | `cdn\\.segment\\.com/analytics\\.js` | 100 | Customer data platform |
| SendGrid | dns_txt | value |  |  | `sendgrid\\.net` | 100 | Transactional email |
| Sentry | script | value |  |  | `browser\\.sentry-cdn\\.com` | 100 | Error monitoring |
| Shopify | header | name |  |  | `X-ShopId` | 100 | Ecommerce |
| Shopify | html | value |  |  | `cdn\\.shopify\\.com` | 100 | Ecommerce |
| Stripe | header | name |  |  | `X-Stripe-.*` | 100 | Payments |
| Stripe | script | value |  |  | `js\\.stripe\\.com/v3` | 100 | Payments |
| WordPress | html | value |  |  | `/wp-content/` | 100 | CMS |
| WordPress | html | value |  |  | `/wp-includes/` | 100 | CMS |
| Zendesk | script | value |  |  | `static\\.zdassets\\.com` | 100 | Customer support |

## Channels

Normalized channels are `header`, `script`, `cookie`, `html`, `meta`, `js`, `dns_txt`, `dns_cname`, `dns_mx` (see `schemas/fingerprint-database.schema.json` and `internal/model/signals.go`). The bundled database uses a subset: `header`, `script`, `cookie`, `html`, `dns_txt`, `dns_cname`, `dns_mx`.

Origins scope `script` patterns to their HTML source type: `html:script-src` and `html:script-src-absolute` for external `scriptSrc`, `html:inline-script` for inline `script` content. Other channels have no origins. Categories (e.g. Payments, Analytics) are descriptive metadata and do not affect detection.

## Inspecting and validating

```console
technograph fingerprints
technograph fingerprints --technology hubspot --format table
technograph fingerprints --channel script --channel header
technograph fingerprints --fingerprints custom.json
technograph fingerprints --fingerprints custom.json --validate
```

- `technograph fingerprints` lists the bundled catalog (permissive external loading reports skipped-pattern warnings to stderr).
- `--technology` is repeatable, case-insensitive exact match; `--channel` accepts only the nine normalized channels (union).
- `--validate` requires `--fingerprints <file>` and strictly validates via `fingerprint.Load(data, true)` with no output on success. It proves the file can be loaded and compiled, not that a technology will match a live site.
- Filtering and table display make no network requests. The original `output.json` assignment artifact is unchanged.
