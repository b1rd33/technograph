package extract

import (
	"net/url"
	"strings"
	"testing"
)

func BenchmarkDocumentExtraction(b *testing.B) {
	base, _ := url.Parse("https://example.com/")
	chunk := `<meta name="generator" content="Example"><a href="/pricing">Pricing</a>` +
		`<script src="/assets/app.js"></script><script>window.analytics={};gtag('config','G-1')</script>`
	body := []byte("<!doctype html><html><head>" + strings.Repeat(chunk, 100) + "</head><body>/wp-content/</body></html>")
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		signals, links, _, err := DocumentWithLinks(body, base)
		if err != nil || len(signals) == 0 || len(links) == 0 {
			b.Fatalf("signals=%d links=%d error=%v", len(signals), len(links), err)
		}
	}
}
