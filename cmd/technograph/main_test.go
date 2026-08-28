package main

import "testing"

func TestStructuredCommandDispatchPreservesLegacyFlags(t *testing.T) {
	for _, command := range []string{"scan", "explain", "validate", "fingerprints", "compare", "help", "-h", "--help"} {
		if !isStructuredCommand(command) {
			t.Errorf("%q should be structured", command)
		}
	}
	for _, legacy := range []string{"-version", "domains.txt"} {
		if isStructuredCommand(legacy) {
			t.Errorf("%q should retain legacy dispatch", legacy)
		}
	}
}
