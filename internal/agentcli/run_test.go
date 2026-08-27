package agentcli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateAcceptsInterspersedFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{
		"validate", "example.com", "--output", "",
	}, strings.NewReader(""), &stdout, &stderr, nil)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	var result struct {
		SchemaVersion string `json:"schema_version"`
		Results       []struct {
			Status string `json:"status"`
			Domain string `json:"domain"`
		} `json:"results"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != "1.0" || len(result.Results) != 1 || result.Results[0].Domain != "example.com" {
		t.Fatalf("result = %#v", result)
	}
}

func TestDashOutputMeansStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{
		"validate", "example.com", "--output=-",
	}, strings.NewReader(""), &stdout, &stderr, nil)
	if code != 0 || !bytes.Contains(stdout.Bytes(), []byte(`"domain": "example.com"`)) {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
}

func TestValidateReportsInvalidDomainAsData(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"validate", "https://example.com"}, strings.NewReader(""), &stdout, &stderr, nil)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"status": "invalid"`)) ||
		!bytes.Contains(stdout.Bytes(), []byte(`"code": "INVALID_DOMAIN"`)) {
		t.Fatalf("stdout = %s", stdout.Bytes())
	}
}

func TestIntersperseRejectsUnknownFlags(t *testing.T) {
	_, err := intersperse([]string{"example.com", "--mystery"}, map[string]bool{})
	if err == nil {
		t.Fatal("expected an error")
	}
}
