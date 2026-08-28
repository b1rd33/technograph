package agentapi

import (
	"fmt"
	"sort"

	"github.com/b1rd33/technograph/internal/model"
)

// TechnologyExplanation is a deterministic claim backed only by matcher
// evidence already present in the scan result.
type TechnologyExplanation struct {
	Technology string           `json:"technology"`
	Categories []string         `json:"categories"`
	Evidence   []model.Evidence `json:"evidence"`
}

// GroundedExplanation is optimized for agent consumption: it contains no
// inferred technologies, generated confidence, or unsupported prose.
type GroundedExplanation struct {
	SchemaVersion string                  `json:"schema_version"`
	Domain        string                  `json:"domain"`
	Status        Status                  `json:"status"`
	Overview      string                  `json:"overview"`
	Technologies  []TechnologyExplanation `json:"technologies"`
	Warnings      []Issue                 `json:"warnings"`
	Errors        []Issue                 `json:"errors"`
}

// Explain converts one scan result into evidence-grouped deterministic claims.
func Explain(result DomainResult) GroundedExplanation {
	domain := result.Domain
	if domain == "" {
		domain = result.Input
	}
	overview := fmt.Sprintf("No configured technology fingerprint matched %s (scan status: %s).", domain, result.Status)
	if len(result.Technologies) > 0 {
		overview = fmt.Sprintf("Observed %d configured technologies for %s (scan status: %s); every technology below is backed by matching fingerprint evidence.", len(result.Technologies), domain, result.Status)
	}
	technologies := make([]TechnologyExplanation, 0, len(result.Technologies))
	for _, name := range result.Technologies {
		categories := append([]string{}, result.TechnologyCategories[name]...)
		sort.Strings(categories)
		evidence := make([]model.Evidence, 0)
		for _, item := range result.Evidence {
			if item.Technology == name {
				evidence = append(evidence, item)
			}
		}
		technologies = append(technologies, TechnologyExplanation{
			Technology: name, Categories: categories, Evidence: evidence,
		})
	}
	return GroundedExplanation{
		SchemaVersion: SchemaVersion, Domain: domain, Status: result.Status,
		Overview: overview, Technologies: technologies,
		Warnings: append([]Issue{}, result.Warnings...), Errors: append([]Issue{}, result.Errors...),
	}
}
