package technograph_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestPublishedSchemasAreValidJSON(t *testing.T) {
	paths, err := filepath.Glob("schemas/*.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("schemas: paths=%v error=%v", paths, err)
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil || !json.Valid(data) {
			t.Errorf("invalid schema %s: %v", path, err)
		}
	}
}

func TestAssignmentOutputCoversExactlyTheInputDomains(t *testing.T) {
	domainData, err := os.ReadFile("domains.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Fields(string(domainData))
	sort.Strings(want)
	outputData, err := os.ReadFile("output.json")
	if err != nil {
		t.Fatal(err)
	}
	var output map[string][]string
	if err := json.Unmarshal(outputData, &output); err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(output))
	for domain, technologies := range output {
		got = append(got, domain)
		if technologies == nil {
			t.Errorf("%s has null technologies; want an array", domain)
		}
		if !sort.StringsAreSorted(technologies) {
			t.Errorf("%s technologies are not sorted: %v", domain, technologies)
		}
	}
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("output domains = %v, want %v", got, want)
	}
}
