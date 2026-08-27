package agentapi

import (
	"context"
	"testing"
	"time"

	"github.com/b1rd33/technograph/internal/app"
	"github.com/b1rd33/technograph/internal/model"
)

type stubHTTP struct{}

func (stubHTTP) Probe(context.Context, string) (model.HTTPResult, []model.Signal) {
	return model.HTTPResult{StatusCode: 200}, []model.Signal{{Channel: model.ChannelHeader, Name: "cf-ray"}}
}

type stubDNS struct{}

func (stubDNS) Probe(context.Context, string) (model.DNSResult, []model.Signal) {
	return model.DNSResult{Status: map[string]string{"mx": "nodata", "txt": "nodata", "cname": "nodata"}}, nil
}

func testRunner(t *testing.T) Runner {
	t.Helper()
	service, _, err := app.New(app.Options{
		FingerprintData:    []byte(`{"schema_version":1,"technologies":{"Cloudflare":{"header":"cf-ray"}}}`),
		StrictFingerprints: true, HTTP: stubHTTP{}, DNS: stubDNS{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	return Runner{Service: service, Now: func() time.Time { return time.Unix(1, 0) }}
}

func TestRunnerReturnsTypedInvalidAndSuccessfulResults(t *testing.T) {
	report, err := testRunner(t).Scan(context.Background(), "request-1", []string{"bad", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Results[0].Status != StatusInvalid || report.Results[1].Status != StatusOK {
		t.Fatalf("results = %#v", report.Results)
	}
	if got := report.Results[1].Technologies; len(got) != 1 || got[0] != "Cloudflare" {
		t.Fatalf("technologies = %v", got)
	}
	if report.Summary.Invalid != 1 || report.Summary.OK != 1 {
		t.Fatalf("summary = %#v", report.Summary)
	}
}

func TestRunnerCapsAutonomousBatchSize(t *testing.T) {
	runner := testRunner(t)
	runner.MaxDomains = 1
	if _, err := runner.Scan(context.Background(), "", []string{"example.com", "example.org"}); err == nil {
		t.Fatal("expected maximum-domain error")
	}
}

func TestDiffSuppressesRemovalAfterFailedScan(t *testing.T) {
	before := Report{Results: []DomainResult{{Domain: "example.com", Status: StatusOK, Technologies: []string{"Cloudflare"}}}}
	after := Report{Results: []DomainResult{{Domain: "example.com", Status: StatusFailed, Technologies: []string{}}}}
	diff := Diff(before, after, time.Unix(2, 0))
	if len(diff.Changes) != 0 || len(diff.Uncertain) != 1 {
		t.Fatalf("diff = %#v", diff)
	}
}
