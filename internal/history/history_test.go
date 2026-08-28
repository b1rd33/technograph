package history

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/b1rd33/technograph/internal/agentapi"
)

const testDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func TestStoreSavesPrivateImmutableHistoryNewestFirst(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	store := Store{Root: root}
	first := fixtureReport(time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC), "first", []string{"Stripe"})
	second := fixtureReport(time.Date(2026, 8, 28, 11, 0, 0, 0, time.UTC), "second", []string{"Stripe", "Cloudflare"})
	if _, err := store.Save(first, "v1", testDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save(second, "v1", testDigest); err != nil {
		t.Fatal(err)
	}
	report, err := store.History("example.com", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Entries) != 2 || report.Entries[0].RequestID != "second" || report.Entries[1].RequestID != "first" {
		t.Fatalf("entries = %#v", report.Entries)
	}
	latest, err := store.Latest("example.com")
	if err != nil || latest.RequestID != "second" || latest.FingerprintDigest != testDigest {
		t.Fatalf("latest=%#v error=%v", latest, err)
	}
	directory := filepath.Join(root, domainKey("example.com"))
	items, _ := os.ReadDir(directory)
	for _, item := range items {
		info, err := item.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("entry mode = %o", info.Mode().Perm())
		}
	}
	if _, err := store.Save(second, "v1", testDigest); err == nil {
		t.Fatal("duplicate immutable entry was overwritten")
	}
}

func TestStoreSkipsInvalidResultsAndReportsMissingHistory(t *testing.T) {
	t.Parallel()
	store := Store{Root: t.TempDir()}
	report := fixtureReport(time.Now(), "invalid", nil)
	report.Results[0].Domain = ""
	report.Results[0].Status = agentapi.StatusInvalid
	entries, err := store.Save(report, "v1", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil || len(entries) != 0 {
		t.Fatalf("entries=%v error=%v", entries, err)
	}
	if _, err := store.Latest("example.com"); !errors.Is(err, ErrNoHistory) {
		t.Fatalf("Latest error = %v", err)
	}
}

func TestStoreRejectsCorruptEntry(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	directory := filepath.Join(root, domainKey("example.com"))
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "bad.json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Store{Root: root}).Latest("example.com"); err == nil {
		t.Fatal("corrupt entry was ignored")
	}
}

func fixtureReport(at time.Time, requestID string, technologies []string) agentapi.Report {
	return agentapi.Report{
		SchemaVersion: agentapi.SchemaVersion, RequestID: requestID, GeneratedAt: at,
		Results: []agentapi.DomainResult{{
			InputIndex: 0, Input: "example.com", Domain: "example.com", Apex: "example.com",
			Status: agentapi.StatusOK, Technologies: technologies,
			Warnings: []agentapi.Issue{}, Errors: []agentapi.Issue{},
		}},
	}
}
