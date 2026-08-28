package agentapi

import (
	"time"

	"github.com/b1rd33/technograph/internal/fingerprint"
	"github.com/b1rd33/technograph/internal/model"
)

const SchemaVersion = "1.0"

type Status string

const (
	StatusOK      Status = "ok"
	StatusPartial Status = "partial"
	StatusBlocked Status = "blocked"
	StatusFailed  Status = "failed"
	StatusInvalid Status = "invalid"
)

type Issue struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Channel string `json:"channel,omitempty"`
}

type DomainResult struct {
	InputIndex           int                 `json:"input_index"`
	Input                string              `json:"input"`
	Domain               string              `json:"domain,omitempty"`
	Apex                 string              `json:"apex,omitempty"`
	Status               Status              `json:"status"`
	Technologies         []string            `json:"technologies"`
	TechnologyCategories map[string][]string `json:"technology_categories,omitempty"`
	Evidence             []model.Evidence    `json:"evidence,omitempty"`
	HTTP                 *model.HTTPResult   `json:"http,omitempty"`
	DNS                  *model.DNSResult    `json:"dns,omitempty"`
	Warnings             []Issue             `json:"warnings"`
	Errors               []Issue             `json:"errors"`
	ElapsedMS            int64               `json:"elapsed_ms"`
}

type Summary struct {
	Requested  int `json:"requested"`
	OK         int `json:"ok"`
	Partial    int `json:"partial"`
	Blocked    int `json:"blocked"`
	Failed     int `json:"failed"`
	Invalid    int `json:"invalid"`
	Detections int `json:"detections"`
}

type Report struct {
	SchemaVersion string         `json:"schema_version"`
	RequestID     string         `json:"request_id"`
	GeneratedAt   time.Time      `json:"generated_at"`
	Results       []DomainResult `json:"results"`
	Summary       Summary        `json:"summary"`
}

type FingerprintInventory struct {
	SchemaVersion string                   `json:"schema_version"`
	Count         int                      `json:"count"`
	Fingerprints  []fingerprint.Descriptor `json:"fingerprints"`
}

type JSONLRecord struct {
	Type          string        `json:"type"`
	SchemaVersion string        `json:"schema_version"`
	RequestID     string        `json:"request_id"`
	GeneratedAt   *time.Time    `json:"generated_at,omitempty"`
	Result        *DomainResult `json:"result,omitempty"`
	Summary       *Summary      `json:"summary,omitempty"`
}
