package agentcli

import (
	"strings"
	"testing"

	"github.com/b1rd33/technograph/internal/agentapi"
	"github.com/b1rd33/technograph/internal/model"
)

func formatFixture() agentapi.Report {
	return agentapi.Report{
		Summary: agentapi.Summary{Requested: 2, OK: 1, Invalid: 1, Detections: 2},
		Results: []agentapi.DomainResult{
			{
				Domain: "shopify.com", Status: agentapi.StatusOK,
				Technologies:         []string{"Cloudflare", "Shopify"},
				TechnologyCategories: map[string][]string{"Cloudflare": {"CDN"}, "Shopify": {"Ecommerce"}},
				HTTP:                 &model.HTTPResult{StatusCode: 200, FinalURL: "https://www.shopify.com/"},
				DNS:                  &model.DNSResult{Status: map[string]string{"mx": "ok", "txt": "ok", "cname": "nodata"}},
				Warnings:             []agentapi.Issue{}, Errors: []agentapi.Issue{}, ElapsedMS: 438,
			},
			{
				Input: "=invalid", Status: agentapi.StatusInvalid, Technologies: []string{},
				Warnings: []agentapi.Issue{}, Errors: []agentapi.Issue{{Code: "INVALID_DOMAIN", Message: "bad, input"}},
			},
		},
	}
}

func TestRenderTableIsCompactAndIncludesSummary(t *testing.T) {
	t.Parallel()
	output := string(renderTable(formatFixture()))
	for _, want := range []string{"DOMAIN", "shopify.com", "Cloudflare, Shopify", "CDN, Ecommerce", "2 domains, 2 detections"} {
		if !strings.Contains(output, want) {
			t.Fatalf("table missing %q:\n%s", want, output)
		}
	}
}

func TestRenderCSVIsSpreadsheetSafeAndQuoted(t *testing.T) {
	t.Parallel()
	data, err := renderCSV(formatFixture())
	if err != nil {
		t.Fatal(err)
	}
	output := string(data)
	if !strings.HasPrefix(output, "domain,status,technologies,categories,") {
		t.Fatalf("unexpected header: %s", output)
	}
	if !strings.Contains(output, `shopify.com,ok,Cloudflare; Shopify,CDN; Ecommerce,200`) {
		t.Fatalf("missing result row: %s", output)
	}
	if !strings.Contains(output, `'=invalid,invalid`) || !strings.Contains(output, `"INVALID_DOMAIN: bad, input"`) {
		t.Fatalf("CSV injection or quoting guard missing: %s", output)
	}
}

func TestSafeCSVCellProtectsCommonFormulaPrefixes(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"=SUM(A1)", "+1", "-1", "@command", "  =formula"} {
		if got := safeCSVCell(value); !strings.HasPrefix(got, "'") {
			t.Fatalf("safeCSVCell(%q) = %q", value, got)
		}
	}
	if got := safeCSVCell("stripe.com"); got != "stripe.com" {
		t.Fatalf("safe value changed to %q", got)
	}
}
