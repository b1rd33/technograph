package technograph_test

import (
	"encoding/json"
	"regexp"
	"testing"

	technograph "github.com/christiannikolov/technograph"
)

type fingerprintFile struct {
	SchemaVersion int `json:"schema_version"`
	Technologies  map[string]struct {
		Patterns []struct {
			Channel string `json:"channel"`
			Regex   string `json:"regex"`
		} `json:"patterns"`
	} `json:"technologies"`
}

func TestDefaultFingerprintFixture(t *testing.T) {
	t.Parallel()

	var fixture fingerprintFile
	if err := json.Unmarshal(technograph.DefaultFingerprints(), &fixture); err != nil {
		t.Fatalf("decode embedded fingerprints: %v", err)
	}
	if fixture.SchemaVersion != 1 {
		t.Fatalf("schema version = %d, want 1", fixture.SchemaVersion)
	}
	if got := len(fixture.Technologies); got != 16 {
		t.Fatalf("technology count = %d, want 16", got)
	}

	patternCount := 0
	for technology, definition := range fixture.Technologies {
		if len(definition.Patterns) == 0 {
			t.Errorf("%s has no patterns", technology)
		}
		for _, pattern := range definition.Patterns {
			patternCount++
			if pattern.Channel == "" {
				t.Errorf("%s has an empty channel", technology)
			}
			if _, err := regexp.Compile("(?i)" + pattern.Regex); err != nil {
				t.Errorf("%s pattern %q does not compile: %v", technology, pattern.Regex, err)
			}
		}
	}
	if patternCount != 24 {
		t.Fatalf("pattern count = %d, want 24", patternCount)
	}
}

func TestDefaultFingerprintsReturnsACopy(t *testing.T) {
	t.Parallel()

	first := technograph.DefaultFingerprints()
	second := technograph.DefaultFingerprints()
	first[0] = 'x'
	if second[0] == 'x' {
		t.Fatal("DefaultFingerprints returned mutable shared storage")
	}
}
