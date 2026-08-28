package agentapi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/b1rd33/technograph/internal/model"
)

func TestScanReportJSONContract(t *testing.T) {
	report := Report{
		SchemaVersion: SchemaVersion,
		RequestID:     "contract-request",
		GeneratedAt:   time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC),
		Results: []DomainResult{{
			InputIndex: 0, Input: "example.com", Domain: "example.com", Apex: "example.com",
			Status: StatusOK, Technologies: []string{"Cloudflare"},
			Evidence: []model.Evidence{{
				Technology: "Cloudflare", Channel: model.ChannelHeader, Pattern: "cf-ray",
				Matched: "cf-ray", Origin: "http:final-header", Confidence: 100,
			}},
			HTTP:     &model.HTTPResult{RequestedURL: "https://example.com", FinalURL: "https://example.com/", StatusCode: 200},
			DNS:      &model.DNSResult{Apex: "example.com", MX: []string{}, TXT: []string{}, CNAME: []string{}},
			Warnings: []Issue{}, Errors: []Issue{}, ElapsedMS: 25,
		}},
		Summary: Summary{Requested: 1, OK: 1, Detections: 1},
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimSpace(`{
  "schema_version": "1.0",
  "request_id": "contract-request",
  "generated_at": "2026-08-28T12:00:00Z",
  "results": [
    {
      "input_index": 0,
      "input": "example.com",
      "domain": "example.com",
      "apex": "example.com",
      "status": "ok",
      "technologies": [
        "Cloudflare"
      ],
      "evidence": [
        {
          "technology": "Cloudflare",
          "channel": "header",
          "pattern": "cf-ray",
          "matched": "cf-ray",
          "origin": "http:final-header",
          "confidence": 100
        }
      ],
      "http": {
        "requested_url": "https://example.com",
        "final_url": "https://example.com/",
        "status_code": 200,
        "redirects": 0,
        "body_bytes": 0,
        "body_truncated": false,
        "blocked": false,
        "challenge": false
      },
      "dns": {
        "apex": "example.com",
        "mx": [],
        "txt": [],
        "cname": []
      },
      "warnings": [],
      "errors": [],
      "elapsed_ms": 25
    }
  ],
  "summary": {
    "requested": 1,
    "ok": 1,
    "partial": 0,
    "blocked": 0,
    "failed": 0,
    "invalid": 0,
    "detections": 1
  }
}`)
	if string(data) != want {
		t.Fatalf("scan report contract changed:\n%s", data)
	}
}
