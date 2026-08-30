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

func TestRunHelpUsesStdoutAndSucceeds(t *testing.T) {
	for _, help := range []string{"-h", "--help"} {
		t.Run(help, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), []string{help}, &stdout, &stderr, nil)
			if code != 0 {
				t.Fatalf("code = %d", code)
			}
			if !bytes.Contains(stdout.Bytes(), []byte("Usage: technograph [flags] domains.txt")) {
				t.Fatalf("stdout = %q", stdout.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q", stderr.String())
			}
		})
	}
}

func TestLegacyCLIRoutesThroughSafeNetwork(t *testing.T) {
	options := legacyAppOptions(nil, true, 10, 8e9, 3e9, nil, false, nil)
	if !options.SafeNetwork {
		t.Fatal("legacy CLI must enable SafeNetwork")
	}
	if options.DomainTimeout <= 0 {
		t.Fatal("legacy options must set DomainTimeout")
	}
}
