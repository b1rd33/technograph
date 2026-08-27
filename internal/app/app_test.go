package app

import (
	"context"
	"testing"
	"time"

	"github.com/b1rd33/technograph/internal/model"
)

type stubHTTP struct{}

func (stubHTTP) Probe(context.Context, string) (model.HTTPResult, []model.Signal) {
	return model.HTTPResult{StatusCode: 200}, []model.Signal{{
		Channel: model.ChannelHeader, Name: "cf-ray", Origin: "test",
	}}
}

type stubDNS struct{}

func (stubDNS) Probe(context.Context, string) (model.DNSResult, []model.Signal) {
	return model.DNSResult{}, nil
}

func TestServiceScansWithInjectedProbes(t *testing.T) {
	fingerprints := []byte(`{
  "schema_version": 1,
  "technologies": {
    "Cloudflare": {"patterns": [{"channel": "header", "regex": "cf-ray"}]}
  }
}`)
	service, warnings, err := New(Options{
		FingerprintData: fingerprints, StrictFingerprints: true,
		HTTP: stubHTTP{}, DNS: stubDNS{}, Concurrency: 2, DomainTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v", warnings)
	}

	results := service.Scan(context.Background(), []model.Domain{{Hostname: "example.com", Apex: "example.com"}})
	if len(results) != 1 || len(results[0].Technologies) != 1 || results[0].Technologies[0] != "Cloudflare" {
		t.Fatalf("results = %#v", results)
	}
}

func TestNewRejectsInvalidFingerprintsBeforeConstructingProbes(t *testing.T) {
	_, _, err := New(Options{FingerprintData: []byte("not json"), StrictFingerprints: true})
	if err == nil {
		t.Fatal("expected an error")
	}
}
