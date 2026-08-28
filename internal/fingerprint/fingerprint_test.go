package fingerprint

import (
	"encoding/json"
	"strings"
	"testing"

	technograph "github.com/b1rd33/technograph"
	"github.com/b1rd33/technograph/internal/model"
)

func defaultEngine(t *testing.T) *Engine {
	t.Helper()
	database, warnings, err := Load(technograph.DefaultFingerprints(), true)
	if err != nil {
		t.Fatalf("Load default fingerprints: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if database.Count() != 24 {
		t.Fatalf("pattern count = %d, want 24", database.Count())
	}
	return NewEngine(database)
}

func TestAllRequiredTechnologiesDetect(t *testing.T) {
	t.Parallel()
	engine := defaultEngine(t)
	signals := []model.Signal{
		{Channel: model.ChannelScript, Value: "https://js.hs-scripts.com/123.js", Origin: "script-src"},
		{Channel: model.ChannelScript, Value: "https://js.stripe.com/v3/", Origin: "script-src"},
		{Channel: model.ChannelScript, Value: "gtag('config', 'G-1')", Origin: "inline-script"},
		{Channel: model.ChannelScript, Value: "https://widget.intercom.io/widget/x", Origin: "script-src"},
		{Channel: model.ChannelHeader, Name: "CF-RAY", Value: "abc", Origin: "header"},
		{Channel: model.ChannelHTML, Value: `<link href="/wp-content/theme.css">`, Origin: "body"},
		{Channel: model.ChannelHTML, Value: `<script src="https://cdn.shopify.com/a.js">`, Origin: "body"},
		{Channel: model.ChannelDNSTXT, Value: "include:sendgrid.net", Origin: "dns"},
		{Channel: model.ChannelDNSTXT, Value: "hubspot-developer-verification=abc", Origin: "dns"},
		{Channel: model.ChannelDNSCNAME, Value: "site.salesforce.com", Origin: "dns"},
		{Channel: model.ChannelDNSMX, Value: "aspmx.l.google.com", Origin: "dns"},
		{Channel: model.ChannelDNSMX, Value: "tenant.protection.outlook.com", Origin: "dns"},
		{Channel: model.ChannelScript, Value: "https://static.zdassets.com/x.js", Origin: "script-src"},
		{Channel: model.ChannelScript, Value: "https://js.driftt.com/include.js", Origin: "script-src"},
		{Channel: model.ChannelScript, Value: "https://cdn.segment.com/analytics.js/v1/x", Origin: "script-src"},
		{Channel: model.ChannelScript, Value: "https://browser.sentry-cdn.com/8.js", Origin: "script-src"},
		{Channel: model.ChannelScript, Value: "https://static.hotjar.com/c/hotjar.js", Origin: "script-src"},
	}

	got, evidence := engine.Detect(signals)
	want := []string{
		"Cloudflare", "Drift", "Google Analytics 4", "Google Workspace",
		"Hotjar", "HubSpot", "Intercom", "Microsoft 365", "Salesforce",
		"Segment", "SendGrid", "Sentry", "Shopify", "Stripe", "WordPress", "Zendesk",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("detected = %v, want %v", got, want)
	}
	if len(evidence) < len(want) {
		t.Fatalf("evidence count = %d, want at least %d", len(evidence), len(want))
	}
}

func TestHeaderAndCookiePatternsTargetNames(t *testing.T) {
	t.Parallel()
	engine := defaultEngine(t)

	got, _ := engine.Detect([]model.Signal{
		{Channel: model.ChannelHeader, Name: "x-note", Value: "mentions cf-ray"},
		{Channel: model.ChannelCookie, Name: "session", Value: "intercom-session"},
	})
	if len(got) != 0 {
		t.Fatalf("value-only mentions detected %v", got)
	}

	got, _ = engine.Detect([]model.Signal{
		{Channel: model.ChannelHeader, Name: "Cf-Ray", Value: "abc"},
		{Channel: model.ChannelCookie, Name: "intercom-session", Value: "secret"},
	})
	if strings.Join(got, "|") != "Cloudflare|Intercom" {
		t.Fatalf("name detections = %v", got)
	}
}

func TestChannelIsolation(t *testing.T) {
	t.Parallel()
	engine := defaultEngine(t)
	got, _ := engine.Detect([]model.Signal{
		{Channel: model.ChannelHTML, Value: "aspmx.l.google.com"},
		{Channel: model.ChannelDNSTXT, Value: "https://js.stripe.com/v3"},
	})
	if len(got) != 0 {
		t.Fatalf("wrong-channel strings detected %v", got)
	}
}

func TestEvidenceIsDeduplicated(t *testing.T) {
	t.Parallel()
	engine := defaultEngine(t)
	got, evidence := engine.Detect([]model.Signal{
		{Channel: model.ChannelHeader, Name: "cf-ray", Origin: "first"},
		{Channel: model.ChannelHeader, Name: "cf-ray", Origin: "second"},
		{Channel: model.ChannelHeader, Name: "cf-cache-status", Origin: "third"},
	})
	if strings.Join(got, "|") != "Cloudflare" {
		t.Fatalf("detections = %v", got)
	}
	if len(evidence) != 2 {
		t.Fatalf("evidence count = %d, want 2", len(evidence))
	}
}

func TestPatternTags(t *testing.T) {
	t.Parallel()
	expression, confidence, version, err := parseTags(`vendor-([\d.]+)\;confidence:75\;version:\1`)
	if err != nil {
		t.Fatalf("parseTags: %v", err)
	}
	if expression != `vendor-([\d.]+)` || confidence != 75 || version != `\1` {
		t.Fatalf("got expression=%q confidence=%d version=%q", expression, confidence, version)
	}

	expression, _, _, err = parseTags(`literal\;semicolon`)
	if err != nil || expression != `literal\;semicolon` {
		t.Fatalf("literal delimiter = %q, %v", expression, err)
	}
}

func TestExternalUnsupportedRegexReturnsWarning(t *testing.T) {
	t.Parallel()
	payload := rawPayload(t, map[string][]rawPattern{
		"Example": {{Channel: "html", Regex: `(?!unsupported)`}},
		"Working": {{Channel: "html", Regex: `working`}},
	})
	database, warnings, err := Load(payload, false)
	if err != nil {
		t.Fatalf("Load external: %v", err)
	}
	if database.Count() != 1 || len(warnings) != 1 {
		t.Fatalf("count=%d warnings=%v", database.Count(), warnings)
	}
	if _, _, err := Load(payload, true); err == nil {
		t.Fatal("strict load accepted unsupported regex")
	}
}

func TestChannelPatternOrListShape(t *testing.T) {
	t.Parallel()
	payload := []byte(`{"schema_version":1,"technologies":{"Example":{"script":"one","html":["two","three"]}}}`)
	database, warnings, err := Load(payload, true)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Load: warnings=%v error=%v", warnings, err)
	}
	if database.Count() != 3 {
		t.Fatalf("count = %d, want 3", database.Count())
	}
}

func TestTechnologyCategoriesAreNormalizedAndExposed(t *testing.T) {
	t.Parallel()
	payload := []byte(`{"schema_version":1,"technologies":{"Example":{"category":"Analytics","categories":["Marketing","Analytics"],"html":"example"}}}`)
	database, warnings, err := Load(payload, true)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Load: warnings=%v error=%v", warnings, err)
	}
	want := "Analytics|Marketing"
	if got := strings.Join(database.Categories("Example"), "|"); got != want {
		t.Fatalf("categories = %q, want %q", got, want)
	}
	descriptors := database.Descriptors()
	if len(descriptors) != 1 || strings.Join(descriptors[0].Categories, "|") != want {
		t.Fatalf("descriptors = %#v", descriptors)
	}
	returned := database.Categories("Example")
	returned[0] = "mutated"
	if strings.Join(database.Categories("Example"), "|") != want {
		t.Fatal("Categories returned mutable database state")
	}
}

func TestMalformedFingerprintsFailAtLoad(t *testing.T) {
	t.Parallel()
	tests := [][]byte{
		[]byte(`not json`),
		[]byte(`{"schema_version":1,"technologies":{"Bad":{"categories":[""],"html":"x"}}}`),
		rawPayload(t, map[string][]rawPattern{"Empty": {}}),
		rawPayload(t, map[string][]rawPattern{"Bad channel": {{Channel: "unknown", Regex: "x"}}}),
		rawPayload(t, map[string][]rawPattern{"Bad target": {{Channel: "html", Regex: "x", Target: "other"}}}),
		rawPayload(t, map[string][]rawPattern{"Bad confidence": {{Channel: "html", Regex: `x\;confidence:nope`}}}),
	}
	for _, payload := range tests {
		if _, _, err := Load(payload, true); err == nil {
			t.Fatalf("Load(%s) succeeded, want error", payload)
		}
	}
}

func rawPayload(t *testing.T, technologies map[string][]rawPattern) []byte {
	t.Helper()
	source := rawFile{SchemaVersion: 1, Technologies: make(map[string]rawTechnology)}
	for name, patterns := range technologies {
		source.Technologies[name] = rawTechnology{Patterns: patterns}
	}
	payload, err := json.Marshal(source)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return payload
}
