package agentapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDomainJSONLRecordOmitsEventTimestamp(t *testing.T) {
	data, err := json.Marshal(JSONLRecord{
		Type: "domain_result", SchemaVersion: SchemaVersion, RequestID: "request",
		Result: &DomainResult{Status: StatusOK, Technologies: []string{}, Warnings: []Issue{}, Errors: []Issue{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "generated_at") {
		t.Fatalf("unexpected zero timestamp: %s", data)
	}
}
