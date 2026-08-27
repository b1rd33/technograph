package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRunRejectsInvalidInputBeforeFingerprintLoading(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(path, []byte("https://example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{path}, &stdout, &stderr, []byte("not json"))
	if code != 1 {
		t.Fatalf("code = %d", code)
	}
	if !bytes.Contains(stderr.Bytes(), []byte("schemes are not allowed")) {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunVersionNeedsNoInput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"--version"}, &stdout, &stderr, nil)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("technograph dev")) {
		t.Fatalf("stdout = %q", stdout.String())
	}
}
