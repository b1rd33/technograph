package agentapi

import (
	"sort"
	"time"
)

type ChangeKind string

const (
	ChangeAdded   ChangeKind = "added"
	ChangeRemoved ChangeKind = "removed"
)

type TechnologyChange struct {
	Domain     string     `json:"domain"`
	Technology string     `json:"technology"`
	Kind       ChangeKind `json:"kind"`
}

type UncertainChange struct {
	Domain string `json:"domain"`
	Reason string `json:"reason"`
}

type DiffReport struct {
	SchemaVersion string             `json:"schema_version"`
	GeneratedAt   time.Time          `json:"generated_at"`
	BeforeID      string             `json:"before_request_id,omitempty"`
	AfterID       string             `json:"after_request_id,omitempty"`
	Changes       []TechnologyChange `json:"changes"`
	Uncertain     []UncertainChange  `json:"uncertain"`
}

// Diff compares observations conservatively. Additions from partial scans are
// useful, but removals are emitted only after a complete successful scan.
func Diff(before, after Report, generatedAt time.Time) DiffReport {
	previous := indexResults(before.Results)
	current := indexResults(after.Results)
	domains := make(map[string]struct{}, len(previous)+len(current))
	for key := range previous {
		domains[key] = struct{}{}
	}
	for key := range current {
		domains[key] = struct{}{}
	}
	ordered := make([]string, 0, len(domains))
	for key := range domains {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)

	report := DiffReport{
		SchemaVersion: SchemaVersion, GeneratedAt: generatedAt.UTC(),
		BeforeID: before.RequestID, AfterID: after.RequestID,
		Changes: []TechnologyChange{}, Uncertain: []UncertainChange{},
	}
	for _, key := range ordered {
		old, hadOld := previous[key]
		newResult, hasNew := current[key]
		if !hasNew {
			report.Uncertain = append(report.Uncertain, UncertainChange{Domain: key, Reason: "domain is missing from the current snapshot"})
			continue
		}
		oldSet := stringSet(old.Technologies)
		newSet := stringSet(newResult.Technologies)
		for technology := range newSet {
			if _, existed := oldSet[technology]; !hadOld || !existed {
				report.Changes = append(report.Changes, TechnologyChange{Domain: key, Technology: technology, Kind: ChangeAdded})
			}
		}
		if !hadOld {
			continue
		}
		if newResult.Status != StatusOK {
			for technology := range oldSet {
				if _, stillPresent := newSet[technology]; !stillPresent {
					report.Uncertain = append(report.Uncertain, UncertainChange{Domain: key, Reason: "possible removals suppressed because current scan status is " + string(newResult.Status)})
					break
				}
			}
			continue
		}
		for technology := range oldSet {
			if _, stillPresent := newSet[technology]; !stillPresent {
				report.Changes = append(report.Changes, TechnologyChange{Domain: key, Technology: technology, Kind: ChangeRemoved})
			}
		}
	}
	sort.Slice(report.Changes, func(i, j int) bool {
		if report.Changes[i].Domain != report.Changes[j].Domain {
			return report.Changes[i].Domain < report.Changes[j].Domain
		}
		if report.Changes[i].Technology != report.Changes[j].Technology {
			return report.Changes[i].Technology < report.Changes[j].Technology
		}
		return report.Changes[i].Kind < report.Changes[j].Kind
	})
	return report
}

func indexResults(results []DomainResult) map[string]DomainResult {
	indexed := make(map[string]DomainResult, len(results))
	for _, result := range results {
		key := result.Domain
		if key == "" {
			key = result.Input
		}
		indexed[key] = result
	}
	return indexed
}

func stringSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}
