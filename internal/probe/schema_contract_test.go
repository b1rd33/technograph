package probe

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/b1rd33/technograph/internal/model"
)

// TestScanReportSchemaTruncationReasonsContract is the single source-of-truth
// schema test. It reads schemas/scan-report.schema.json and inspects the real
// signals_truncated_reasons.items.enum at both homepage and secondary-page
// locations. Expected values are derived from model.TruncationReason constants.
func TestScanReportSchemaTruncationReasonsContract(t *testing.T) {
	t.Parallel()
	schemaPath := filepath.Join("..", "..", "schemas", "scan-report.schema.json")
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read %s: %v", schemaPath, err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	defs, ok := schema["$defs"].(map[string]any)
	if !ok {
		t.Fatal("$defs missing")
	}
	httpDef, _ := defs["http"].(map[string]any)
	httpPageDef, _ := defs["httpPage"].(map[string]any)
	if httpDef == nil || httpPageDef == nil {
		t.Fatal("http or httpPage def missing")
	}
	extract := func(def map[string]any, name string) []string {
		t.Helper()
		props, _ := def["properties"].(map[string]any)
		field, _ := props[name].(map[string]any)
		items, _ := field["items"].(map[string]any)
		rawEnum, _ := items["enum"].([]any)
		got := make([]string, 0, len(rawEnum))
		for _, v := range rawEnum {
			s, _ := v.(string)
			got = append(got, s)
		}
		return got
	}
	homepageEnum := extract(httpDef, "signals_truncated_reasons")
	secondaryEnum := extract(httpPageDef, "signals_truncated_reasons")

	expected := []model.TruncationReason{
		model.ReasonLinks, model.ReasonSignals, model.ReasonInlineScripts, model.ReasonWindowNames,
		model.ReasonHeaders, model.ReasonCookieCount, model.ReasonCookieBytes, model.ReasonCookieValue,
	}
	expectedStrings := make([]string, 0, len(expected))
	for _, r := range expected {
		expectedStrings = append(expectedStrings, string(r))
	}
	sortedExpected := append([]string(nil), expectedStrings...)
	sort.Strings(sortedExpected)

	assertEnum := func(label string, got []string) {
		t.Helper()
		if len(got) != len(sortedExpected) {
			t.Fatalf("%s enum len = %d (%v), want %d (%v)", label, len(got), got, len(sortedExpected), sortedExpected)
		}
		sortedGot := append([]string(nil), got...)
		sort.Strings(sortedGot)
		for i := range sortedExpected {
			if sortedGot[i] != sortedExpected[i] {
				t.Fatalf("%s enum[%d] = %q, want %q (got %v)", label, i, sortedGot[i], sortedExpected[i], got)
			}
		}
		// no duplicates, no unknown
		seen := make(map[string]bool, len(got))
		for _, v := range got {
			if seen[v] {
				t.Fatalf("%s duplicate enum value %q", label, v)
			}
			seen[v] = true
		}
		if seen["unknown"] {
			t.Fatalf("%s contains unexpected 'unknown'", label)
		}
		// each model constant serializes to expected JSON string
		for _, r := range expected {
			b, _ := json.Marshal(r)
			var s string
			_ = json.Unmarshal(b, &s)
			if s != string(r) {
				t.Fatalf("TruncationReason %q JSON %q mismatch", string(r), s)
			}
			if !seen[s] {
				t.Fatalf("%s missing expected reason %q", label, s)
			}
		}
	}
	assertEnum("http ($defs/http/properties/signals_truncated_reasons/items/enum)", homepageEnum)
	assertEnum("httpPage ($defs/httpPage/properties/signals_truncated_reasons/items/enum)", secondaryEnum)

	// homepage and secondary-page enums must be identical (sorted)
	sortedHome := append([]string(nil), homepageEnum...)
	sortedPage := append([]string(nil), secondaryEnum...)
	sort.Strings(sortedHome)
	sort.Strings(sortedPage)
	for i := range sortedHome {
		if sortedHome[i] != sortedPage[i] {
			t.Fatalf("http vs httpPage enum mismatch at %d: %q vs %q", i, sortedHome[i], sortedPage[i])
		}
	}
}
