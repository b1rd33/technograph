package extract

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/b1rd33/technograph/internal/model"
)

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %q: %v", raw, err)
	}
	return u
}

func reasonsContain(reasons []model.TruncationReason, want model.TruncationReason) bool {
	for _, r := range reasons {
		if r == want {
			return true
		}
	}
	return false
}

func assertReasons(t *testing.T, got []model.TruncationReason, want ...model.TruncationReason) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("reasons len = %d (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("reasons[%d] = %q, want %q (got %v)", i, got[i], want[i], got)
		}
	}
}

func TestDetailedReasonsLinks(t *testing.T) {
	t.Parallel()
	base := mustParseURL(t, "https://example.com/")
	body := strings.Repeat(`<a href="/p">x</a>`, 5001)
	_, _, truncated, reasons, err := DocumentWithLinksDetailed([]byte(body), base)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated || !reasonsContain(reasons, model.ReasonLinks) {
		t.Fatalf("expected links reason, got %v truncated=%v", reasons, truncated)
	}
}

func TestDetailedReasonsLinksInvalidAfterLimitNoFalsePositive(t *testing.T) {
	t.Parallel()
	base := mustParseURL(t, "https://example.com/")
	var b strings.Builder
	for i := 0; i < 5000; i++ {
		b.WriteString(`<a href="/p">x</a>`)
	}
	// invalid href (missing/empty/whitespace or parse error) after limit — must not add links reason
	b.WriteString(`<a>no href</a><a href="">empty</a><a href="   ">spaces</a><a href="http://[invalid">bad</a>`)
	_, _, truncated, reasons, err := DocumentWithLinksDetailed([]byte(b.String()), base)
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Fatalf("expected not truncated for invalid anchors after limit, got %v", reasons)
	}
	if reasonsContain(reasons, model.ReasonLinks) {
		t.Fatalf("invalid anchors must not produce links reason: %v", reasons)
	}
}

func TestDetailedReasonsExactLimitNotTruncated(t *testing.T) {
	t.Parallel()
	base := mustParseURL(t, "https://example.com/")
	body := strings.Repeat(`<a href="/p">x</a>`, 5000)
	_, _, truncated, reasons, err := DocumentWithLinksDetailed([]byte(body), base)
	if err != nil {
		t.Fatal(err)
	}
	if truncated || len(reasons) != 0 {
		t.Fatalf("exact 5000 links should not be truncated, got %v %v", truncated, reasons)
	}
	// 1 html:body + 4999 metas = 5000 signals, not truncated.
	body2 := ""
	for i := 0; i < 4999; i++ {
		body2 += `<meta name="x" content="y">`
	}
	signals, _, truncated2, reasons2, err := DocumentWithLinksDetailed([]byte(body2), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = signals
	if truncated2 || len(reasons2) != 0 {
		t.Fatalf("exact 4999 metas + html:body = 5000 signals should not truncate, got %v %v", truncated2, reasons2)
	}
}

func TestDetailedReasonsSignalsAbsoluteEdge(t *testing.T) {
	t.Parallel()
	// 1 html + 4999 metas = 5000, next script with absolute duplicate must not falsely truncate if no work omitted.
	base := mustParseURL(t, "https://example.com/")
	var b strings.Builder
	for i := 0; i < 4999; i++ {
		b.WriteString(`<meta name="x" content="y">`)
	}
	// absolute src that resolves to absolute — at limit exactly after primary? Actually we have 5000 already (1 html + 4999 meta)
	// Adding a script src that would need 1 more would be truncated correctly.
	// Test the non-truncation path: 1 html + 4998 metas = 4999, script with src and distinct absolute needs 2 signals → second would overflow.
	b.Reset()
	for i := 0; i < 4998; i++ {
		b.WriteString(`<meta name="x" content="y">`)
	}
	// This script needs 2 signals: src + absolute → total would be 5001, so one should be dropped and reason signals.
	b.WriteString(`<script src="/a.js"></script>`)
	_, _, truncated, reasons, err := DocumentWithLinksDetailed([]byte(b.String()), base)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated || !reasonsContain(reasons, model.ReasonSignals) {
		t.Fatalf("expected signals truncation for absolute duplicate overflow, got %v", reasons)
	}
	// Now test that a script at exact limit without absolute candidate does NOT truncate.
	b.Reset()
	for i := 0; i < 4998; i++ {
		b.WriteString(`<meta name="x" content="y">`)
	}
	// src with no distinct absolute (absolute same as source or base nil) — total 5000 exactly.
	b.WriteString(`<script src="https://other.example/a.js"></script>`)
	_, _, truncated2, reasons2, err := DocumentWithLinksDetailed([]byte(b.String()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if truncated2 || len(reasons2) != 0 {
		t.Fatalf("exact 5000 with non-absolute script should not truncate, got %v %v", truncated2, reasons2)
	}
}

func TestDetailedReasonsEmptyMetaAfterLimitNoFalsePositive(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	for i := 0; i < 4999; i++ {
		b.WriteString(`<meta name="x" content="y">`)
	}
	// Now at 5000 signals (1 html + 4999 meta). Next meta is empty — must not create false signals reason.
	b.WriteString(`<meta><meta name="" content="">`)
	_, _, truncated, reasons, err := DocumentWithLinksDetailed([]byte(b.String()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if truncated || len(reasons) != 0 {
		t.Fatalf("empty meta after limit must not truncate, got %v %v", truncated, reasons)
	}
}

func TestDetailedReasonsInlineScripts(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	for i := 0; i < 51; i++ {
		b.WriteString(`<script>window.foo = 1;</script>`)
	}
	_, _, truncated, reasons, err := DocumentWithLinksDetailed([]byte(b.String()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated || !reasonsContain(reasons, model.ReasonInlineScripts) {
		t.Fatalf("expected inline_scripts, got %v", reasons)
	}
}

func TestDetailedReasonsWindowNames(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString("<script>")
	for i := 0; i < 800; i++ {
		b.WriteString(fmt.Sprintf("window.var%d = 1; ", i))
	}
	b.WriteString("</script>")
	_, _, truncated, reasons, err := DocumentWithLinksDetailed([]byte(b.String()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated || !reasonsContain(reasons, model.ReasonWindowNames) {
		t.Fatalf("expected window_names, got %v", reasons)
	}
}

func TestDetailedReasonsSignals(t *testing.T) {
	t.Parallel()
	base := mustParseURL(t, "https://example.com/")
	body := strings.Repeat(`<script src="/a.js"></script>`, 4000)
	_, _, truncated, reasons, err := DocumentWithLinksDetailed([]byte(body), base)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated || !reasonsContain(reasons, model.ReasonSignals) {
		t.Fatalf("expected signals, got %v", reasons)
	}
}

func TestDetailedReasonsSortedAndDeduped(t *testing.T) {
	t.Parallel()
	base := mustParseURL(t, "https://example.com/")
	var b strings.Builder
	b.WriteString("<html><body>")
	for i := 0; i < 6000; i++ {
		b.WriteString(`<a href="/p">x</a>`)
	}
	for i := 0; i < 6000; i++ {
		b.WriteString(`<script src="/a.js"></script>`)
	}
	b.WriteString("</body></html>")
	_, _, truncated, reasons, err := DocumentWithLinksDetailed([]byte(b.String()), base)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Fatal("expected truncated")
	}
	if len(reasons) < 2 {
		t.Fatalf("expected at least 2 reasons, got %v", reasons)
	}
	for i := 1; i < len(reasons); i++ {
		if string(reasons[i-1]) > string(reasons[i]) {
			t.Fatalf("not sorted: %v", reasons)
		}
		if reasons[i-1] == reasons[i] {
			t.Fatalf("duplicate: %v", reasons)
		}
	}
}

func TestLegacyShimCompatible(t *testing.T) {
	t.Parallel()
	base := mustParseURL(t, "https://example.com/")
	body := strings.Repeat(`<a href="/p">x</a>`, 5001)
	_, _, truncOld, err := DocumentWithLinks([]byte(body), base)
	if err != nil {
		t.Fatal(err)
	}
	_, _, truncNew, reasons, err := DocumentWithLinksDetailed([]byte(body), base)
	if err != nil {
		t.Fatal(err)
	}
	if truncOld != truncNew {
		t.Fatalf("shim mismatch trunc %v vs %v", truncOld, truncNew)
	}
	if truncNew && len(reasons) == 0 {
		t.Fatal("detailed should have reasons when truncated")
	}
}

func TestFirstOverLimitSetsCorrectReason(t *testing.T) {
	t.Parallel()
	base := mustParseURL(t, "https://example.com/")
	var b strings.Builder
	for i := 0; i < 5000; i++ {
		b.WriteString(`<a href="/p">x</a>`)
	}
	b.WriteString(`<a href="/extra">one more valid</a>`)
	_, _, _, reasons, _ := DocumentWithLinksDetailed([]byte(b.String()), base)
	assertReasons(t, reasons, model.ReasonLinks)
}
