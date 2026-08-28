package agentcli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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

func TestHelpUsesStdoutAndSucceeds(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"top-level long", []string{"--help"}, "technograph scan"},
		{"top-level short", []string{"-h"}, "technograph validate"},
		{"scan", []string{"scan", "--help"}, "Usage: technograph scan"},
		{"explain", []string{"explain", "--help"}, "Usage: technograph explain"},
		{"validate", []string{"validate", "-h"}, "Usage: technograph validate"},
		{"fingerprints", []string{"fingerprints", "--help"}, "Usage: technograph fingerprints"},
		{"fingerprint import", []string{"fingerprints", "import", "--help"}, "Usage: technograph fingerprints import"},
		{"compare", []string{"compare", "-h"}, "Usage: technograph compare"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), test.args, strings.NewReader(""), &stdout, &stderr, nil)
			if code != 0 {
				t.Fatalf("code = %d, stderr = %q", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), test.want) {
				t.Fatalf("stdout = %q, want %q", stdout.String(), test.want)
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q", stderr.String())
			}
		})
	}
}

func TestFingerprintImportWritesNormalizedDatabaseAndReport(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "technologies.json")
	output := filepath.Join(directory, "normalized.json")
	report := filepath.Join(directory, "compatibility.json")
	if err := os.WriteFile(input, []byte(`{"Example":{"headers":{"server":"example"},"url":"unsupported"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{
		"fingerprints", "import", "--input", input, "--output", output, "--report", report,
	}, strings.NewReader(""), &stdout, &stderr, nil)
	if code != 0 || stdout.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	for _, path := range []string{output, report} {
		data, err := os.ReadFile(path)
		if err != nil || !json.Valid(data) {
			t.Fatalf("artifact %s: valid=%v error=%v", path, json.Valid(data), err)
		}
	}
	if !strings.Contains(stderr.String(), "imported 1 technologies and 1 patterns; skipped 1") {
		t.Fatalf("stderr = %q", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run(context.Background(), []string{
		"fingerprints", "import", "--input", input, "--strict", "--output", filepath.Join(directory, "strict.json"),
	}, strings.NewReader(""), &stdout, &stderr, nil)
	if code != 1 || !strings.Contains(stderr.String(), "strict import rejected") {
		t.Fatalf("strict code=%d stderr=%q", code, stderr.String())
	}
}

func TestHelpAfterDoubleDashIsTreatedAsInput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"validate", "--", "--help"}, strings.NewReader(""), &stdout, &stderr, nil)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"status": "invalid"`)) {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestTopLevelHelpExplainsInterfaces(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"--help"}, strings.NewReader(""), &stdout, &stderr, nil)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	for _, want := range []string{
		"Technograph detects technologies", "Commands:",
		"scan          Scan domains and return JSON, JSONL, table, or CSV",
		"explain       Scan domains and print a human-readable evidence report",
		"Use technograph-mcp", "assignment compatibility",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestSubcommandHelpIncludesExamples(t *testing.T) {
	for _, command := range []string{"scan", "explain", "validate", "fingerprints", "compare"} {
		t.Run(command, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), []string{command, "--help"}, strings.NewReader(""), &stdout, &stderr, nil)
			if code != 0 || stderr.Len() != 0 {
				t.Fatalf("code = %d, stderr = %q", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), "Examples:") || !strings.Contains(stdout.String(), "technograph "+command) {
				t.Fatalf("stdout = %q", stdout.String())
			}
		})
	}
}
