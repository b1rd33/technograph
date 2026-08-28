package importer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b1rd33/technograph/internal/fingerprint"
)

func TestImportConvertsSupportedFieldsAndReportsEverythingElse(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	source := `{
  "Example": {
    "cats": [1],
    "scriptSrc": ["cdn\\.example", "cdn\\.example"],
    "headers": {"server": "example"},
    "cookies": {"example_session": ""},
    "meta": {"generator": ["Example"]},
    "dns": {"MX": "mail\\.example", "A": "192\\.0\\.2\\.1"},
    "html": "(?=unsupported)",
    "js": {"Example.version": ".+"},
    "url": "example"
  }
}`
	categories := `{"1":{"name":"Web framework"}}`
	sourcePath := filepath.Join(directory, "e.json")
	categoryPath := filepath.Join(directory, "categories.json")
	writeFixture(t, sourcePath, source)
	writeFixture(t, categoryPath, categories)

	database, report, err := Import(Options{Input: directory, CategoriesPath: categoryPath})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.SourceFiles != 1 || report.Summary.TechnologiesSeen != 1 || report.Summary.TechnologiesImported != 1 {
		t.Fatalf("summary = %#v", report.Summary)
	}
	if report.Summary.PatternsSeen != 10 || report.Summary.PatternsImported != 5 || report.Summary.PatternsSkipped != 5 ||
		report.Summary.DuplicatesRemoved != 1 || report.Summary.UnsupportedRegexes != 1 {
		t.Fatalf("summary = %#v", report.Summary)
	}
	definition := database.Technologies["Example"]
	if strings.Join(definition.Categories, "|") != "Web framework" || len(definition.Patterns) != 5 {
		t.Fatalf("definition = %#v", definition)
	}
	var selectorCount int
	var scopedScriptCount int
	for _, pattern := range definition.Patterns {
		if pattern.Selector != "" {
			selectorCount++
		}
		if pattern.Channel == "script" && len(pattern.Origins) == 2 {
			scopedScriptCount++
		}
	}
	if selectorCount != 3 {
		t.Fatalf("selector pattern count = %d", selectorCount)
	}
	if scopedScriptCount != 1 {
		t.Fatalf("scoped script pattern count = %d", scopedScriptCount)
	}
	encoded, _ := json.Marshal(database)
	compiled, warnings, err := fingerprint.Load(encoded, true)
	if err != nil || len(warnings) != 0 || compiled.Count() != 5 {
		t.Fatalf("compiled=%v warnings=%v error=%v", compiled, warnings, err)
	}
	for _, kind := range []string{"duplicate", "unsupported_channel", "unsupported_regex"} {
		if !hasIssue(report, kind) {
			t.Fatalf("report lacks %q: %#v", kind, report.Issues)
		}
	}
}

func TestImportTechnologyFilterIsExact(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "technologies.json")
	writeFixture(t, path, `{"Alpha":{"html":"alpha"},"Beta":{"html":"beta"}}`)
	database, report, err := Import(Options{Input: path, Technologies: []string{"Beta"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(database.Technologies) != 1 || len(database.Technologies["Beta"].Patterns) != 1 || report.Summary.TechnologiesSeen != 1 {
		t.Fatalf("database=%#v report=%#v", database, report)
	}
	if _, _, err := Import(Options{Input: path, Technologies: []string{"Missing"}}); err == nil {
		t.Fatal("missing selected technology was accepted")
	}
}

func TestImportRejectsMalformedAndNormalizedSources(t *testing.T) {
	t.Parallel()
	for name, data := range map[string]string{
		"malformed.json":  `{"Example":{"headers":[]}}`,
		"normalized.json": `{"schema_version":1,"technologies":{}}`,
	} {
		path := filepath.Join(t.TempDir(), name)
		writeFixture(t, path, data)
		if _, _, err := Import(Options{Input: path}); err == nil {
			t.Fatalf("Import(%s) succeeded", name)
		}
	}
}

func hasIssue(report Report, kind string) bool {
	for _, issue := range report.Issues {
		if issue.Kind == kind {
			return true
		}
	}
	return false
}

func writeFixture(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}
