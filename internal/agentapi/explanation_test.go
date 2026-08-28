package agentapi

import (
	"strings"
	"testing"

	"github.com/b1rd33/technograph/internal/model"
)

func TestExplainGroupsOnlyMatchingEvidence(t *testing.T) {
	result := DomainResult{
		Domain: "example.com", Status: StatusPartial,
		Technologies:         []string{"Cloudflare", "Stripe"},
		TechnologyCategories: map[string][]string{"Stripe": {"Payments"}},
		Evidence: []model.Evidence{
			{Technology: "Stripe", Channel: model.ChannelScript, Matched: "js.stripe.com/v3"},
			{Technology: "Cloudflare", Channel: model.ChannelHeader, Matched: "cf-ray"},
		},
		Warnings: []Issue{}, Errors: []Issue{{Code: "DNS_QUERY_FAILED"}},
	}
	explanation := Explain(result)
	if len(explanation.Technologies) != 2 || explanation.Technologies[0].Technology != "Cloudflare" || len(explanation.Technologies[0].Evidence) != 1 {
		t.Fatalf("explanation = %#v", explanation)
	}
	if strings.Contains(explanation.Overview, "confidence") || explanation.Status != StatusPartial || len(explanation.Errors) != 1 {
		t.Fatalf("explanation = %#v", explanation)
	}
}
