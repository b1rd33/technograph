package main

import "testing"

func TestStructuredCommandDispatchPreservesLegacyFlags(t *testing.T) {
	for _, command := range []string{"scan", "validate", "fingerprints", "compare", "help"} {
		if !isStructuredCommand(command) {
			t.Errorf("%q should be structured", command)
		}
	}
	for _, legacy := range []string{"-h", "--help", "-version", "domains.txt"} {
		if isStructuredCommand(legacy) {
			t.Errorf("%q should retain legacy dispatch", legacy)
		}
	}
}
