package agentcli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b1rd33/technograph/internal/fingerprint"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func bundledData(t *testing.T) []byte {
	t.Helper()
	return nil
}

func TestFingerprintsUnfilteredJSONShapeCompatible(t *testing.T) {
	// Capture unfiltered JSON and verify it is the same FingerprintInventory shape.
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"fingerprints"}, strings.NewReader(""), &stdout, &stderr, bundledFromEmbed(t))
	if code != 0 {
		t.Fatalf("code %d stderr %q", code, stderr.String())
	}
	var inv struct {
		SchemaVersion string `json:"schema_version"`
		Count         int    `json:"count"`
		Fingerprints  []struct {
			Technology string `json:"technology"`
			Channel    string `json:"channel"`
		} `json:"fingerprints"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &inv); err != nil {
		t.Fatal(err)
	}
	if inv.SchemaVersion != "1.0" || inv.Count != len(inv.Fingerprints) {
		t.Fatalf("inventory mismatch: %v", inv)
	}
	if inv.Count == 0 {
		t.Fatal("expected non-zero count")
	}
	// Ensure deterministic ordering is preserved (already sorted by Descriptors); second run identical.
	var stdout2, stderr2 bytes.Buffer
	code2 := Run(context.Background(), []string{"fingerprints"}, strings.NewReader(""), &stdout2, &stderr2, bundledFromEmbed(t))
	if code2 != 0 || stdout.String() != stdout2.String() {
		t.Fatal("deterministic output mismatch")
	}
}

func TestFingerprintsOutputFlagRemains(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "inv.json")
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"fingerprints", "--output", out}, strings.NewReader(""), &stdout, &stderr, bundledFromEmbed(t))
	if code != 0 || stdout.Len() != 0 {
		t.Fatalf("code %d stdout %q stderr %q", code, stdout.String(), stderr.String())
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var inv struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(data, &inv); err != nil {
		t.Fatal(err)
	}
	if inv.Count == 0 {
		t.Fatal("output file empty")
	}
}

func TestFingerprintsExternalInventoryRemains(t *testing.T) {
	// Build a minimal external normalized DB as JSON fixture via fingerprint.Load path.
	payload := []byte(`{"schema_version":1,"technologies":{"A":{"patterns":[{"channel":"html","regex":"a"}]}}}`)
	tmp := filepath.Join(t.TempDir(), "custom.json")
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout2, stderr2 bytes.Buffer
	code2 := Run(context.Background(), []string{"fingerprints", "--fingerprints", tmp}, strings.NewReader(""), &stdout2, &stderr2, bundledFromEmbed(t))
	if code2 != 0 {
		t.Fatalf("code %d stderr %q", code2, stderr2.String())
	}
	var inv struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(stdout2.Bytes(), &inv); err != nil {
		t.Fatal(err)
	}
	if inv.Count != 1 {
		t.Fatalf("external count %d want 1", inv.Count)
	}
}

func TestFingerprintsTechnologyFilters(t *testing.T) {
	bundled := bundledFromEmbed(t)
	// HubSpot exact and case-insensitive
	cases := []struct {
		args []string
		want int
		name string
	}{
		{[]string{"fingerprints", "--technology", "HubSpot"}, 3, "HubSpot"},
		{[]string{"fingerprints", "--technology", "hubspot"}, 3, "hubspot lower"},
		{[]string{"fingerprints", "--technology", "HubSpot", "--technology", "Stripe"}, 5, "union two"},
		{[]string{"fingerprints", "--technology", "UnknownXYZ"}, 0, "unknown empty"},
	}
	for _, c := range cases {
		var stdout, stderr bytes.Buffer
		code := Run(context.Background(), c.args, strings.NewReader(""), &stdout, &stderr, bundled)
		if code != 0 {
			t.Fatalf("%s code %d stderr %q", c.name, code, stderr.String())
		}
		var inv struct {
			Count        int `json:"count"`
			Fingerprints []struct {
				Technology string `json:"technology"`
			} `json:"fingerprints"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &inv); err != nil {
			t.Fatal(err)
		}
		if inv.Count != c.want || len(inv.Fingerprints) != c.want {
			t.Fatalf("%s count %d want %d body %s", c.name, inv.Count, c.want, stdout.String())
		}
		if c.name == "union two" {
			// ordering preserved: descriptors sorted globally, filtered preserves that order.
			// First should be HubSpot (before Stripe lexicographically) and last Stripe.
			if inv.Fingerprints[0].Technology != "HubSpot" {
				t.Fatalf("ordering first %q want HubSpot", inv.Fingerprints[0].Technology)
			}
		}
	}
}

func TestFingerprintsChannelFilters(t *testing.T) {
	bundled := bundledFromEmbed(t)
	// Every supported channel accepted
	for _, ch := range []string{"header", "script", "cookie", "html", "meta", "js", "dns_txt", "dns_cname", "dns_mx"} {
		var stdout, stderr bytes.Buffer
		code := Run(context.Background(), []string{"fingerprints", "--channel", ch}, strings.NewReader(""), &stdout, &stderr, bundled)
		if code != 0 {
			t.Fatalf("channel %s code %d stderr %q", ch, code, stderr.String())
		}
	}
	// Union
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"fingerprints", "--channel", "script", "--channel", "header"}, strings.NewReader(""), &stdout, &stderr, bundled)
	if code != 0 {
		t.Fatalf("channel union code %d", code)
	}
	var inv struct {
		Fingerprints []struct {
			Channel string `json:"channel"`
		} `json:"fingerprints"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &inv); err != nil {
		t.Fatal(err)
	}
	for _, f := range inv.Fingerprints {
		if f.Channel != "script" && f.Channel != "header" {
			t.Fatalf("channel union leaked %q", f.Channel)
		}
	}
	if len(inv.Fingerprints) == 0 {
		t.Fatal("channel union empty")
	}
	// Unknown channel → exit 2
	var stdout2, stderr2 bytes.Buffer
	code2 := Run(context.Background(), []string{"fingerprints", "--channel", "bogus"}, strings.NewReader(""), &stdout2, &stderr2, bundled)
	if code2 != 2 {
		t.Fatalf("unknown channel code %d want 2 stderr %q", code2, stderr2.String())
	}
}

func TestFingerprintsFormats(t *testing.T) {
	bundled := bundledFromEmbed(t)
	// Default is json
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"fingerprints"}, strings.NewReader(""), &stdout, &stderr, bundled)
	if code != 0 || !json.Valid(stdout.Bytes()) {
		t.Fatalf("json default not valid")
	}
	// Table
	var stdout2, stderr2 bytes.Buffer
	code2 := Run(context.Background(), []string{"fingerprints", "--format", "table"}, strings.NewReader(""), &stdout2, &stderr2, bundled)
	if code2 != 0 || !strings.Contains(stdout2.String(), "TECHNOLOGY") {
		t.Fatalf("table code %d stdout %q", code2, stdout2.String())
	}
	// Invalid format → 2
	var stdout3, stderr3 bytes.Buffer
	code3 := Run(context.Background(), []string{"fingerprints", "--format", "yaml"}, strings.NewReader(""), &stdout3, &stderr3, bundled)
	if code3 != 2 {
		t.Fatalf("invalid format code %d", code3)
	}
	// Tabs/newlines sanitized in table (no extra rows/cols via payload)
	// We test by passing a technology filter containing tab is not possible via CLI, so instead we test sanitizeTableCell directly
	// by ensuring table output has exactly Count+1 lines (header + rows)
	var stdout4 bytes.Buffer
	var stderr4 bytes.Buffer
	code4 := Run(context.Background(), []string{"fingerprints", "--technology", "HubSpot", "--format", "table"}, strings.NewReader(""), &stdout4, &stderr4, bundled)
	if code4 != 0 {
		t.Fatalf("hubspot table code %d", code4)
	}
	lines := strings.Count(strings.TrimSuffix(stdout4.String(), "\n"), "\n") + 1
	// header + 3 HubSpot patterns = 4 lines
	if lines != 4 {
		t.Fatalf("hubspot table lines %d want 4 got %q", lines, stdout4.String())
	}
	// sanitizeTableCell unit
	if got := sanitizeTableCell("a\tb\nc"); got != "a b c" {
		t.Fatalf("sanitize %q", got)
	}
}

func TestFingerprintsValidate(t *testing.T) {
	dir := t.TempDir()
	validPayload := []byte(`{"schema_version":1,"technologies":{"A":{"patterns":[{"channel":"html","regex":"a"}]}}}`)
	validPath := filepath.Join(dir, "valid.json")
	if err := os.WriteFile(validPath, validPayload, 0o600); err != nil {
		t.Fatal(err)
	}

	// Valid exits 0 empty stdout
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"fingerprints", "--fingerprints", validPath, "--validate"}, strings.NewReader(""), &stdout, &stderr, bundledFromEmbed(t))
	if code != 0 || stdout.Len() != 0 {
		t.Fatalf("validate valid code %d stdout %q stderr %q", code, stdout.String(), stderr.String())
	}
	// Explicit --format json with --validate is accepted as harmless explicit default, empty stdout
	var sJSON, eJSON bytes.Buffer
	codeJSON := Run(context.Background(), []string{"fingerprints", "--fingerprints", validPath, "--validate", "--format", "json"}, strings.NewReader(""), &sJSON, &eJSON, bundledFromEmbed(t))
	if codeJSON != 0 || sJSON.Len() != 0 {
		t.Fatalf("validate --format json code %d stdout %q stderr %q", codeJSON, sJSON.String(), eJSON.String())
	}
	if eJSON.Len() != 0 {
		t.Fatalf("validate --format json expected empty stderr for valid DB, got %q", eJSON.String())
	}
	// Missing --fingerprints → 2
	var s2, e2 bytes.Buffer
	code2 := Run(context.Background(), []string{"fingerprints", "--validate"}, strings.NewReader(""), &s2, &e2, bundledFromEmbed(t))
	if code2 != 2 {
		t.Fatalf("validate missing fingerprints code %d", code2)
	}
	// Invalid schema
	invalidSchema := filepath.Join(dir, "bad-schema.json")
	if err := os.WriteFile(invalidSchema, []byte(`{"schema_version":2,"technologies":{"A":{"patterns":[{"channel":"html","regex":"a"}]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var s3, e3 bytes.Buffer
	code3 := Run(context.Background(), []string{"fingerprints", "--fingerprints", invalidSchema, "--validate"}, strings.NewReader(""), &s3, &e3, bundledFromEmbed(t))
	if code3 != 1 {
		t.Fatalf("validate bad schema code %d stderr %q", code3, e3.String())
	}
	// Unsupported channel
	badChannel := filepath.Join(dir, "bad-channel.json")
	if err := os.WriteFile(badChannel, []byte(`{"schema_version":1,"technologies":{"A":{"patterns":[{"channel":"bogus","regex":"a"}]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var s4, e4 bytes.Buffer
	code4 := Run(context.Background(), []string{"fingerprints", "--fingerprints", badChannel, "--validate"}, strings.NewReader(""), &s4, &e4, bundledFromEmbed(t))
	if code4 != 1 {
		t.Fatalf("validate bad channel code %d stderr %q", code4, e4.String())
	}
	// Invalid RE2
	badRegex := filepath.Join(dir, "bad-regex.json")
	if err := os.WriteFile(badRegex, []byte(`{"schema_version":1,"technologies":{"A":{"patterns":[{"channel":"html","regex":"(?=lookahead)"}]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var s5, e5 bytes.Buffer
	code5 := Run(context.Background(), []string{"fingerprints", "--fingerprints", badRegex, "--validate"}, strings.NewReader(""), &s5, &e5, bundledFromEmbed(t))
	if code5 != 1 {
		t.Fatalf("validate bad regex code %d stderr %q", code5, e5.String())
	}
	// Over-limit: craft a file >10 MiB
	hugePath := filepath.Join(dir, "huge.json")
	huge := bytes.Repeat([]byte("a"), 10<<20+1)
	if err := os.WriteFile(hugePath, huge, 0o600); err != nil {
		t.Fatal(err)
	}
	var s6, e6 bytes.Buffer
	code6 := Run(context.Background(), []string{"fingerprints", "--fingerprints", hugePath, "--validate"}, strings.NewReader(""), &s6, &e6, bundledFromEmbed(t))
	if code6 != 1 {
		t.Fatalf("validate huge code %d", code6)
	}
	// Permissive would warn but strict fails: lookahead pattern is warning in non-strict, error in strict
	lookaheadPayload := []byte(`{"schema_version":1,"technologies":{"A":{"patterns":[{"channel":"html","regex":"a"},{"channel":"html","regex":"(?=b)"}]}}}`)
	lookaheadPath := filepath.Join(dir, "lookahead.json")
	if err := os.WriteFile(lookaheadPath, lookaheadPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	// Permissive inspection should succeed with warning
	var s7, e7 bytes.Buffer
	code7 := Run(context.Background(), []string{"fingerprints", "--fingerprints", lookaheadPath}, strings.NewReader(""), &s7, &e7, bundledFromEmbed(t))
	if code7 != 0 || !strings.Contains(e7.String(), "warning") {
		t.Fatalf("permissive lookahead code %d stderr %q", code7, e7.String())
	}
	var s8, e8 bytes.Buffer
	code8 := Run(context.Background(), []string{"fingerprints", "--fingerprints", lookaheadPath, "--validate"}, strings.NewReader(""), &s8, &e8, bundledFromEmbed(t))
	if code8 != 1 {
		t.Fatalf("validate lookahead should fail strict, got %d stderr %q", code8, e8.String())
	}
	// Invalid flag combos → 2
	for _, args := range [][]string{
		{"fingerprints", "--fingerprints", validPath, "--validate", "--technology", "A"},
		{"fingerprints", "--fingerprints", validPath, "--validate", "--channel", "html"},
		{"fingerprints", "--fingerprints", validPath, "--validate", "--format", "table"},
		{"fingerprints", "--fingerprints", validPath, "--validate", "--output", filepath.Join(dir, "out.json")},
	} {
		var s, e bytes.Buffer
		code := Run(context.Background(), args, strings.NewReader(""), &s, &e, bundledFromEmbed(t))
		if code != 2 {
			t.Fatalf("validate combo %v code %d want 2 stderr %q", args, code, e.String())
		}
	}
}

func TestFingerprintsGendocRowCountAndEscaping(t *testing.T) {
	// Verify bundled DB count matches descriptors and that escaping concept is exercised
	bundled := bundledFromEmbed(t)
	data, _, err := loadFingerprintData("", bundled)
	if err != nil {
		t.Fatal(err)
	}
	db, _, err := fingerprint.Load(data, true)
	if err != nil {
		t.Fatal(err)
	}
	desc := db.Descriptors()
	if len(desc) != db.Count() {
		t.Fatalf("descriptors %d != count %d", len(desc), db.Count())
	}
	if sanitizeTableCell("a\tb\nc") != "a b c" {
		t.Fatalf("sanitize")
	}
}

func bundledFromEmbed(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("fingerprints.json")
	if err != nil {
		data, err = os.ReadFile("../../fingerprints.json")
		if err != nil {
			t.Fatalf("bundled fingerprints.json not found: %v", err)
		}
	}
	return data
}
