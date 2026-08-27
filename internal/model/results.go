package model

import "time"

// HTTPResult contains diagnostics for one homepage request. These fields are
// used by logs and the optional evidence report, not the required output JSON.
type HTTPResult struct {
	RequestedURL  string `json:"requested_url,omitempty"`
	FinalURL      string `json:"final_url,omitempty"`
	StatusCode    int    `json:"status_code,omitempty"`
	Redirects     int    `json:"redirects"`
	ContentType   string `json:"content_type,omitempty"`
	BodyBytes     int    `json:"body_bytes"`
	BodyTruncated bool   `json:"body_truncated"`
	Blocked       bool   `json:"blocked"`
	Challenge     bool   `json:"challenge"`
	BlockReason   string `json:"block_reason,omitempty"`
	Error         string `json:"error,omitempty"`
}

// DNSResult contains normalized apex records and per-type diagnostics.
type DNSResult struct {
	Apex   string            `json:"apex"`
	MX     []string          `json:"mx"`
	TXT    []string          `json:"txt"`
	CNAME  []string          `json:"cname"`
	Status map[string]string `json:"status,omitempty"`
	Errors map[string]string `json:"errors,omitempty"`
}

// ScanResult is the complete auditable result for one input domain.
type ScanResult struct {
	Domain       Domain        `json:"domain"`
	Technologies []string      `json:"technologies"`
	Evidence     []Evidence    `json:"evidence"`
	HTTP         HTTPResult    `json:"http"`
	DNS          DNSResult     `json:"dns"`
	Elapsed      time.Duration `json:"-"`
	ElapsedMS    int64         `json:"elapsed_ms"`
}
