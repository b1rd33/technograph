package buildinfo

import "testing"

func TestString(t *testing.T) {
	version, commit, date := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = version, commit, date })
	Version, Commit, Date = "1.2.3", "abc123", "2026-08-27"
	if got, want := String(), "technograph 1.2.3 (commit abc123, built 2026-08-27)"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
