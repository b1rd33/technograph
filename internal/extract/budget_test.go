package extract

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/b1rd33/technograph/internal/model"
)

func TestDocumentCapsLinksAt5000(t *testing.T) {
	t.Parallel()
	base, _ := url.Parse("https://example.com/")
	body := strings.Repeat(`<a href="/p">x</a>`, 8000)
	signals, links, truncated, err := DocumentWithLinks([]byte(body), base)
	if err != nil {
		t.Fatalf("DocumentWithLinks: %v", err)
	}
	if !truncated {
		t.Fatal("expected truncated=true when links exceed cap")
	}
	if len(links) != maxLinksPerPage {
		t.Fatalf("links = %d, want %d", len(links), maxLinksPerPage)
	}
	found := false
	for _, s := range signals {
		if s.Channel == model.ChannelHTML && s.Origin == "html:body" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("html:body signal missing after truncation")
	}
}

func TestExactly5000LinksIsNotTruncated(t *testing.T) {
	t.Parallel()
	base, _ := url.Parse("https://example.com/")
	body := strings.Repeat(`<a href="/p">x</a>`, 5000)
	_, links, truncated, err := DocumentWithLinks([]byte(body), base)
	if err != nil {
		t.Fatalf("DocumentWithLinks: %v", err)
	}
	if truncated {
		t.Fatal("exactly 5000 links should not be truncated")
	}
	if len(links) != 5000 {
		t.Fatalf("links = %d, want 5000", len(links))
	}
}

func TestDocumentCapsSignalsAt5000(t *testing.T) {
	t.Parallel()
	base, _ := url.Parse("https://example.com/")
	// Many script tags to exceed signal cap. Each has 1 signal (script-src),
	// but 4000 tags * 1 = 4000, need more to exceed 5000 (raw html signal counts too).
	// Use non-nil base so each script tag produces 2 signals (src + absolute).
	body := strings.Repeat(`<script src="/a.js"></script>`, 4000)
	signals, _, truncated, err := DocumentWithLinks([]byte(body), base)
	if err != nil {
		t.Fatalf("DocumentWithLinks: %v", err)
	}
	if !truncated {
		t.Fatal("expected truncated=true when signals exceed cap")
	}
	// 4000 * 2 = 8000 script signals + 1 html = 8001, capped at 5000
	if len(signals) > maxSignalsPerPage {
		t.Fatalf("signals = %d, want <= %d", len(signals), maxSignalsPerPage)
	}
}

func TestDocumentCapsInlineScriptsAt50(t *testing.T) {
	t.Parallel()
	body := strings.Repeat(`<script>window.foo = 1;</script>`, 100)
	signals, _, truncated, err := DocumentWithLinks([]byte(body), nil)
	if err != nil {
		t.Fatalf("DocumentWithLinks: %v", err)
	}
	if !truncated {
		t.Fatal("expected truncated=true when inline scripts exceed cap")
	}
	count := 0
	for _, s := range signals {
		if s.Channel == model.ChannelScript && s.Origin == "html:inline-script" {
			count++
		}
	}
	if count != maxInlineScripts {
		t.Fatalf("inline scripts = %d, want %d", count, maxInlineScripts)
	}
}

func TestDocumentPreservesHTMLBodySignal(t *testing.T) {
	t.Parallel()
	base, _ := url.Parse("https://example.com/")
	body := strings.Repeat(`<a href="/p">x</a>`, 6000)
	signals, _, truncated, err := DocumentWithLinks([]byte(body), base)
	if err != nil {
		t.Fatalf("DocumentWithLinks: %v", err)
	}
	if !truncated {
		t.Fatal("expected truncated=true for 6000 links exceeding cap")
	}
	if len(signals) == 0 || signals[0].Channel != model.ChannelHTML {
		t.Fatalf("first signal should be html:body, got %#v", signals[0])
	}
	if signals[0].Value != body {
		t.Fatalf("html:body value was truncated or altered")
	}
}

func TestDocumentCapsWindowNamesAt512(t *testing.T) {
	t.Parallel()
	// One script containing 800 distinct window names — tests per-script limit
	// with enough distinct names to actually reach 512 (previous pattern only
	// generated 130 distinct due to limited entropy).
	var b strings.Builder
	b.WriteString("<script>")
	for i := 0; i < 800; i++ {
		// Generate distinct names: a<id> where id is unique per iteration
		b.WriteString(fmt.Sprintf("window.var%d = 1; ", i))
	}
	b.WriteString("</script>")
	signals, _, truncated, err := DocumentWithLinks([]byte(b.String()), nil)
	if err != nil {
		t.Fatalf("DocumentWithLinks: %v", err)
	}
	if !truncated {
		t.Fatal("expected truncated=true when window names exceed cap")
	}
	count := 0
	for _, s := range signals {
		if s.Channel == model.ChannelJS {
			count++
		}
	}
	if count != maxWindowNames {
		t.Fatalf("window names = %d, want %d", count, maxWindowNames)
	}
}

func TestNormalSitesUnaffectedByBudgets(t *testing.T) {
	t.Parallel()
	base, _ := url.Parse("https://example.com/")
	body := `<html><head><meta name="generator" content="Example CMS">
		<script src="/a.js"></script><script>window.Intercom = {};</script>
		</head><body><a href="/pricing">Pricing</a><a href="/about">About</a></body></html>`
	signals, links, truncated, err := DocumentWithLinks([]byte(body), base)
	if err != nil {
		t.Fatalf("DocumentWithLinks: %v", err)
	}
	if truncated {
		t.Fatal("normal site should not be truncated")
	}
	if len(links) != 2 {
		t.Fatalf("links = %d, want 2", len(links))
	}
	found := map[model.Channel]int{}
	for _, s := range signals {
		found[s.Channel]++
	}
	if found[model.ChannelHTML] != 1 || found[model.ChannelScript] == 0 {
		t.Fatalf("unexpected signals: %v", found)
	}
}

func TestCrossBudgetAccuracyManyLinksDoNotSuppressScripts(t *testing.T) {
	t.Parallel()
	base, _ := url.Parse("https://example.com/")
	// 5000 links fill the link cap, followed by script/meta tags.
	// With per-type budgets, later signals must still be collected.
	var b strings.Builder
	b.WriteString("<html><body>")
	for i := 0; i < 6000; i++ {
		b.WriteString(`<a href="/p">x</a>`)
	}
	b.WriteString(`<script src="/late.js"></script>`)
	b.WriteString(`<meta name="generator" content="LateCMS">`)
	b.WriteString(`<script>window.lateDetect = 1;</script>`)
	b.WriteString("</body></html>")
	signals, links, truncated, err := DocumentWithLinks([]byte(b.String()), base)
	if err != nil {
		t.Fatalf("DocumentWithLinks: %v", err)
	}
	if !truncated {
		t.Fatal("expected truncated=true when links exceed cap")
	}
	if len(links) != maxLinksPerPage {
		t.Fatalf("links = %d, want %d", len(links), maxLinksPerPage)
	}
	// Late signals must not have been suppressed by link cap.
	found := map[string]bool{}
	for _, s := range signals {
		if s.Channel == model.ChannelScript && s.Value == "/late.js" {
			found["script"] = true
		}
		if s.Channel == model.ChannelMeta && s.Name == "generator" {
			found["meta"] = true
		}
	}
	if !found["script"] {
		t.Fatal("late script-src suppressed by link cap")
	}
	if !found["meta"] {
		t.Fatal("late meta suppressed by link cap")
	}
}
