package model

import (
	"encoding/json"
	"testing"
)

func TestTruncationReasonsJSONStrings(t *testing.T) {
	h := HTTPResult{
		SignalsTruncated:        true,
		SignalsTruncatedReasons: []TruncationReason{ReasonLinks, ReasonHeaders},
	}
	data, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	var reasons []string
	if err := json.Unmarshal(m["signals_truncated_reasons"], &reasons); err != nil {
		t.Fatal(err)
	}
	has := map[string]bool{}
	for _, r := range reasons {
		has[r] = true
	}
	if !has["links"] || !has["headers"] {
		t.Fatalf("reasons %v", reasons)
	}
	var h2 HTTPResult
	if err := json.Unmarshal(data, &h2); err != nil {
		t.Fatal(err)
	}
	if len(h2.SignalsTruncatedReasons) != 2 {
		t.Fatalf("typed round-trip %v", h2.SignalsTruncatedReasons)
	}
	has2 := map[TruncationReason]bool{}
	for _, r := range h2.SignalsTruncatedReasons {
		has2[r] = true
	}
	if !has2[ReasonLinks] || !has2[ReasonHeaders] {
		t.Fatalf("typed round-trip missing %v", h2.SignalsTruncatedReasons)
	}
}

func TestTruncationReasonConstantsAreStrings(t *testing.T) {
	if string(ReasonLinks) != "links" || string(ReasonSignals) != "signals" || string(ReasonHeaders) != "headers" {
		t.Fatalf("constants changed: %q %q %q", ReasonLinks, ReasonSignals, ReasonHeaders)
	}
}
