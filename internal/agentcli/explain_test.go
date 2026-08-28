package agentcli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b1rd33/technograph/internal/agentapi"
	"github.com/b1rd33/technograph/internal/model"
)

func TestRenderExplanationShowsEvidenceCoverageAndIssues(t *testing.T) {
	t.Parallel()
	report := agentapi.Report{
		GeneratedAt: time.Date(2026, time.August, 28, 9, 30, 0, 0, time.UTC),
		Summary:     agentapi.Summary{Requested: 1, Partial: 1, Detections: 2},
		Results: []agentapi.DomainResult{{
			Input: "stripe.com", Domain: "stripe.com", Status: agentapi.StatusPartial,
			Technologies: []string{"Stripe", "Google Workspace"},
			Evidence: []model.Evidence{
				{Technology: "Stripe", Channel: model.ChannelHeader, Matched: "x-stripe-proxy-response", Origin: "http:final-header", Confidence: 100},
				{Technology: "Google Workspace", Channel: model.ChannelDNSMX, Matched: "google.com", Origin: "dns:stripe.com:mx", Confidence: 100},
			},
			HTTP:      &model.HTTPResult{StatusCode: 200, FinalURL: "https://stripe.com/en-bg", Redirects: 1},
			DNS:       &model.DNSResult{Status: map[string]string{"mx": "ok", "txt": "error", "cname": "nodata"}},
			Errors:    []agentapi.Issue{{Code: "DNS_QUERY_FAILED", Channel: "dns_txt", Message: "resolver timeout"}},
			Warnings:  []agentapi.Issue{},
			ElapsedMS: 3082,
		}},
	}

	output := string(renderExplanation(report))
	for _, want := range []string{
		"Generated: 2026-08-28T09:30:00Z",
		"stripe.com  [PARTIAL]",
		"Google Workspace",
		`DNS MX matched "google.com"`,
		"Stripe",
		`HTTP header matched "x-stripe-proxy-response"`,
		"HTTP: 200 https://stripe.com/en-bg (1 redirect)",
		"DNS: MX ok, TXT error, CNAME nodata",
		"error DNS_QUERY_FAILED/dns_txt: resolver timeout",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
	if strings.Index(output, "Google Workspace") > strings.Index(output, "Stripe") {
		t.Fatalf("technologies are not sorted:\n%s", output)
	}
}

func TestRenderExplanationShowsBlockedAndInvalidResults(t *testing.T) {
	t.Parallel()
	report := agentapi.Report{
		GeneratedAt: time.Unix(0, 0),
		Summary:     agentapi.Summary{Requested: 2, Blocked: 1, Invalid: 1, Detections: 1},
		Results: []agentapi.DomainResult{
			{
				Input: "blocked.example", Domain: "blocked.example", Status: agentapi.StatusBlocked,
				Technologies: []string{"Cloudflare"}, Warnings: []agentapi.Issue{{Code: "HTTP_BLOCKED", Channel: "http", Message: "challenge page"}}, Errors: []agentapi.Issue{},
				HTTP: &model.HTTPResult{StatusCode: 403, FinalURL: "https://blocked.example", Blocked: true},
				DNS:  &model.DNSResult{Status: map[string]string{"mx": "nodata", "txt": "nodata", "cname": "nodata"}},
			},
			{
				Input: "https://invalid.example", Status: agentapi.StatusInvalid, Technologies: []string{}, Warnings: []agentapi.Issue{},
				Errors: []agentapi.Issue{{Code: "INVALID_DOMAIN", Message: "schemes are not allowed"}},
			},
		},
	}
	output := string(renderExplanation(report))
	for _, want := range []string{
		"blocked.example  [BLOCKED]", "HTTP: 403 https://blocked.example [blocked]",
		"warning HTTP_BLOCKED/http: challenge page", "https://invalid.example  [INVALID]",
		"Technologies: none detected", "error INVALID_DOMAIN: schemes are not allowed",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}

func TestRenderExplanationRemovesTerminalControlCharacters(t *testing.T) {
	t.Parallel()
	report := agentapi.Report{
		GeneratedAt: time.Unix(0, 0), Summary: agentapi.Summary{Requested: 1, OK: 1, Detections: 1},
		Results: []agentapi.DomainResult{{
			Input: "example.com", Domain: "example.com", Status: agentapi.StatusOK,
			Technologies: []string{"Example\x1b[31m"},
			Evidence:     []model.Evidence{{Technology: "Example\x1b[31m", Channel: model.ChannelHTML, Matched: "bad\nline", Origin: "http\x1b:body", Confidence: 100}},
			Warnings:     []agentapi.Issue{}, Errors: []agentapi.Issue{},
		}},
	}
	output := renderExplanation(report)
	if bytes.Contains(output, []byte{'\x1b'}) || bytes.Contains(output, []byte("bad\nline")) {
		t.Fatalf("terminal control characters leaked:\n%s", output)
	}
}

func TestExplainReportsInvalidInputWithoutNetworkAccess(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"explain", "https://example.com"}, strings.NewReader(""), &stdout, &stderr, assignmentFingerprints(t))
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "https://example.com  [INVALID]") ||
		!strings.Contains(stdout.String(), "error INVALID_DOMAIN") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestExplainReadsStdinAndWritesOutputFile(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "report.txt")
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{
		"explain", "--output", outputPath,
	}, strings.NewReader("# comment\nhttps://invalid.example\n"), &stdout, &stderr, assignmentFingerprints(t))
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty when writing a file", stdout.String())
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("https://invalid.example  [INVALID]")) {
		t.Fatalf("report = %q", data)
	}
}

func TestExplainAcceptsInterspersedFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{
		"explain", "https://invalid.example", "--output=-",
	}, strings.NewReader(""), &stdout, &stderr, assignmentFingerprints(t))
	if code != 0 || !strings.Contains(stdout.String(), "[INVALID]") {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
}

func TestExplainRejectsInvalidRuntimeConfiguration(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{
		"explain", "--timeout=0", "example.com",
	}, strings.NewReader(""), &stdout, &stderr, assignmentFingerprints(t))
	if code != 2 || !strings.Contains(stderr.String(), "must be positive") {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
}

func TestExplainEnforcesDomainLimit(t *testing.T) {
	arguments := []string{"explain"}
	for index := 0; index < agentapi.DefaultMaxDomains+1; index++ {
		arguments = append(arguments, fmt.Sprintf("invalid-%d.example", index))
	}
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), arguments, strings.NewReader(""), &stdout, &stderr, assignmentFingerprints(t))
	if code != 1 || !strings.Contains(stderr.String(), "too many domains") {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
}

func TestExplainReportsOutputFailure(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "missing", "report.txt")
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{
		"explain", "https://invalid.example", "--output", outputPath,
	}, strings.NewReader(""), &stdout, &stderr, assignmentFingerprints(t))
	if code != 1 || !strings.Contains(stderr.String(), "create temporary output") {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
}

func assignmentFingerprints(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../../fingerprints.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}
