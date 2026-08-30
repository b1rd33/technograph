package agentapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/b1rd33/technograph/internal/app"
	"github.com/b1rd33/technograph/internal/model"
)

type truncHTTP struct {
	result model.HTTPResult
}

func (t truncHTTP) Probe(context.Context, string) (model.HTTPResult, []model.Signal) {
	return t.result, nil
}

func TestSignalsTruncatedMakesPartialAndWarningContainsReasons(t *testing.T) {
	service, _, err := app.New(app.Options{
		FingerprintData:    []byte(`{"schema_version":1,"technologies":{"Cloudflare":{"patterns":[{"channel":"header","selector":"cf-ray","regex":"cloudflare"}]}}}`),
		StrictFingerprints: true,
		HTTP: truncHTTP{result: model.HTTPResult{
			StatusCode:              200,
			SignalsTruncated:        true,
			SignalsTruncatedReasons: []model.TruncationReason{model.ReasonHeaders, model.ReasonLinks},
		}},
		DNS: stubDNS{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	report, err := (Runner{Service: service, Now: func() time.Time { return time.Unix(1, 0) }}).Scan(context.Background(), "req", []string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	res := report.Results[0]
	if res.Status != StatusPartial {
		t.Fatalf("status %v want partial", res.Status)
	}
	if len(res.Warnings) == 0 || res.Warnings[0].Code != "SIGNALS_TRUNCATED" {
		t.Fatalf("warnings %v", res.Warnings)
	}
	if !strings.Contains(res.Warnings[0].Message, "headers") || !strings.Contains(res.Warnings[0].Message, "links") {
		t.Fatalf("warning missing reasons: %q", res.Warnings[0].Message)
	}
	// Ensure typed reasons survive JSON as string array (sorted).
	data, _ := json.Marshal(res.HTTP)
	var m map[string]json.RawMessage
	_ = json.Unmarshal(data, &m)
	var reasons []string
	_ = json.Unmarshal(m["signals_truncated_reasons"], &reasons)
	if len(reasons) != 2 {
		t.Fatalf("json reasons %v", reasons)
	}
	hasH, hasL := false, false
	for _, r := range reasons {
		if r == "headers" {
			hasH = true
		}
		if r == "links" {
			hasL = true
		}
	}
	if !hasH || !hasL {
		t.Fatalf("json reasons missing expected values: %v", reasons)
	}
}
