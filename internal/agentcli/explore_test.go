package agentcli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/b1rd33/technograph/internal/agentapi"
)

func renderExplorerTranscript(report agentapi.Report, commands string) string {
	var output bytes.Buffer
	_ = runExplorer(report, strings.NewReader(commands), &output)
	return output.String()
}

func TestExplorerFiltersAndShowsEvidence(t *testing.T) {
	report := agentapi.Report{
		Results: []agentapi.DomainResult{
			{Input: "stripe.com", Domain: "stripe.com", Status: agentapi.StatusOK, Technologies: []string{"Stripe"}, TechnologyCategories: map[string][]string{"Stripe": {"Payments"}}},
			{Input: "shopify.com", Domain: "shopify.com", Status: agentapi.StatusBlocked, Technologies: []string{"Cloudflare", "Shopify"}},
		},
		Summary: agentapi.Summary{Requested: 2, OK: 1, Blocked: 1, Detections: 3},
	}
	output := renderExplorerTranscript(report, "filter payments\nshow 1\nclear\nshow shopify.com\nquit\n")
	for _, want := range []string{"Filter: payments", "stripe.com", "Technograph evidence report", "SHOPIFY.COM"} {
		if !strings.Contains(strings.ToUpper(output), strings.ToUpper(want)) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}

func TestExplorerRejectsUnknownSelectionAndHandlesEOF(t *testing.T) {
	report := agentapi.Report{Results: []agentapi.DomainResult{{Input: "example.com", Domain: "example.com", Status: agentapi.StatusOK}}, Summary: agentapi.Summary{Requested: 1, OK: 1}}
	output := renderExplorerTranscript(report, "show 9\nwat\n")
	if !strings.Contains(output, "domain not found") || !strings.Contains(output, `unknown command "wat"`) {
		t.Fatalf("output = %q", output)
	}
}
