package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestHandleMetaCommandHelp(t *testing.T) {
	for _, help := range []string{"-h", "--help"} {
		t.Run(help, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			handled, code := handleMetaCommand([]string{help}, &stdout, &stderr)
			if !handled || code != 0 {
				t.Fatalf("handled = %v, code = %d", handled, code)
			}
			if !strings.Contains(stdout.String(), "Usage: technograph-mcp") {
				t.Fatalf("stdout = %q", stdout.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q", stderr.String())
			}
		})
	}
}

func TestHandleMetaCommandVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	handled, code := handleMetaCommand([]string{"--version"}, &stdout, &stderr)
	if !handled || code != 0 || !strings.Contains(stdout.String(), "technograph dev") || stderr.Len() != 0 {
		t.Fatalf("handled = %v, code = %d, stdout = %q, stderr = %q", handled, code, stdout.String(), stderr.String())
	}
}

func TestHandleMetaCommandRejectsArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	handled, code := handleMetaCommand([]string{"unexpected"}, &stdout, &stderr)
	if !handled || code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "Usage: technograph-mcp") {
		t.Fatalf("handled = %v, code = %d, stdout = %q, stderr = %q", handled, code, stdout.String(), stderr.String())
	}
}
