package extract

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/b1rd33/technograph/internal/model"
)

func TestHeadersSeparateNamesAndValues(t *testing.T) {
	t.Parallel()
	signals := Headers(http.Header{"CF-Ray": {"abc"}})
	if len(signals) != 1 {
		t.Fatalf("signal count = %d, want 1", len(signals))
	}
	if signals[0].Name != "cf-ray" || signals[0].Value != "abc" {
		t.Fatalf("unexpected signal: %#v", signals[0])
	}
}

func TestCookiesDeduplicateStructuredPairs(t *testing.T) {
	t.Parallel()
	signals := Cookies([]*http.Cookie{
		{Name: "intercom-session", Value: "x"},
		{Name: "intercom-session", Value: "x"},
		{Name: "other", Value: "y"},
	})
	if len(signals) != 2 {
		t.Fatalf("signal count = %d, want 2", len(signals))
	}
	if signals[0].Name != "intercom-session" {
		t.Fatalf("unexpected cookie order: %#v", signals)
	}
}

func TestDocumentExtractsStaticSignals(t *testing.T) {
	t.Parallel()
	body := []byte(`<!doctype html><html><head>
		<meta name="generator" content="Example CMS">
		<script src="//js.hs-scripts.com/123.js"></script>
		<script src="/assets/app.js"></script>
		<script>window.Intercom = {}; window["analytics"] = {}; gtag('config', 'G-1');</script>
	</head><body><link href="/wp-content/style.css"></body></html>`)
	base, _ := url.Parse("https://example.com/home")
	signals, err := Document(body, base)
	if err != nil {
		t.Fatalf("Document: %v", err)
	}

	assertSignal(t, signals, model.ChannelHTML, "", "/wp-content/")
	assertSignal(t, signals, model.ChannelScript, "", "//js.hs-scripts.com/123.js")
	assertSignal(t, signals, model.ChannelScript, "", "https://js.hs-scripts.com/123.js")
	assertSignal(t, signals, model.ChannelScript, "", "https://example.com/assets/app.js")
	assertSignal(t, signals, model.ChannelScript, "", "gtag(")
	assertSignal(t, signals, model.ChannelMeta, "generator", "Example CMS")
	assertSignal(t, signals, model.ChannelJS, "Intercom", "window.Intercom")
	assertSignal(t, signals, model.ChannelJS, "analytics", "window.analytics")
}

func TestDocumentToleratesMalformedHTML(t *testing.T) {
	t.Parallel()
	signals, err := Document([]byte(`<html><script>gtag(`), nil)
	if err != nil {
		t.Fatalf("Document malformed HTML: %v", err)
	}
	assertSignal(t, signals, model.ChannelScript, "", "gtag(")
}

func TestDocumentWithLinksResolvesNavigationCandidates(t *testing.T) {
	t.Parallel()
	base, _ := url.Parse("https://example.com/products/")
	_, links, err := DocumentWithLinks([]byte(`<a href="../pricing?source=nav#plans">Pricing</a>
		<a href="https://other.example/contact">External</a><a href="#top">Top</a>`), base)
	if err != nil {
		t.Fatalf("DocumentWithLinks: %v", err)
	}
	want := []string{"https://example.com/pricing?source=nav#plans", "https://other.example/contact", "https://example.com/products/#top"}
	if strings.Join(links, "\n") != strings.Join(want, "\n") {
		t.Fatalf("links = %#v, want %#v", links, want)
	}
}

func TestInlineScriptIsBounded(t *testing.T) {
	t.Parallel()
	body := `<script>` + strings.Repeat("x", maxInlineScriptBytes+100) + `</script>`
	signals, err := Document([]byte(body), nil)
	if err != nil {
		t.Fatalf("Document: %v", err)
	}
	for _, signal := range signals {
		if signal.Channel == model.ChannelScript && signal.Origin == "html:inline-script" {
			if len(signal.Value) != maxInlineScriptBytes {
				t.Fatalf("inline size = %d, want %d", len(signal.Value), maxInlineScriptBytes)
			}
			return
		}
	}
	t.Fatal("inline script signal not found")
}

func assertSignal(t *testing.T, signals []model.Signal, channel model.Channel, name, contains string) {
	t.Helper()
	for _, signal := range signals {
		if signal.Channel == channel && (name == "" || signal.Name == name) && strings.Contains(signal.Value, contains) {
			return
		}
	}
	t.Fatalf("missing channel=%s name=%q containing %q in %#v", channel, name, contains, signals)
}
