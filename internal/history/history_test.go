package history

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func TestStoreRejectsOversizedRequestIDAtSave(t *testing.T) {
	t.Parallel()
	store := Store{Root: t.TempDir()}
	oversized := make([]byte, maxRequestIDLen+1)
	for i := range oversized {
		oversized[i] = 'r'
	}
	report := fixtureReport(time.Now(), string(oversized), nil)
	report.Results[0].Domain = "example.com"
	report.Results[0].Status = agentapi.StatusOK
	if _, err := store.Save(report, "v1", testDigest); err == nil {
		t.Fatal("expected Save to reject request_id exceeding 256 bytes")
	}
	if _, err := store.Latest("example.com"); !errors.Is(err, ErrNoHistory) {
		t.Fatalf("Latest error = %v, want ErrNoHistory (entry should not have been written)", err)
	}
}

func TestStoreEnforcesEntrySizeBeforeCommit(t *testing.T) {
	t.Parallel()
	store := Store{Root: t.TempDir()}
	huge := make([]byte, maximumEntrySize+1)
	for i := range huge {
		huge[i] = 'x'
	}
	largeTech := string(huge)
	report := fixtureReport(time.Now(), "big", []string{largeTech})
	report.Results[0].Domain = "example.com"
	report.Results[0].Status = agentapi.StatusOK
	if _, err := store.Save(report, "v1", testDigest); err == nil {
		t.Fatal("expected Save to reject entry exceeding 16 MiB")
	}
	if _, err := store.Latest("example.com"); !errors.Is(err, ErrNoHistory) {
		t.Fatalf("Latest error = %v, want ErrNoHistory (oversized entry should not have been committed)", err)
	}
}

func TestStorePrunesOldestAtMaximumEntries(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, domainKey("example.com"))
	const limit = 5
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < limit; i++ {
		path := filepath.Join(directory, fmt.Sprintf("20260102T100000.00000000%dZ-aaaa-%04d.json", i, i))
		entry := Entry{
			SchemaVersion: SchemaVersion,
			ID:            fmt.Sprintf("20260102T100000.00000000%dZ-aaaa-%04d", i, i),
			RecordedAt:    time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Nanosecond),
			RequestID:     "seed",
			Result:        agentapi.DomainResult{Domain: "example.com", Status: agentapi.StatusOK},
		}
		data, err := json.MarshalIndent(entry, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, '\n')
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := pruneHistoryDirectoryWithLimit(directory, limit); err != nil {
		t.Fatalf("prune at limit: %v", err)
	}
	items, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	jsonCount := 0
	for _, item := range items {
		if item.Type().IsRegular() && strings.HasSuffix(item.Name(), ".json") {
			jsonCount++
		}
	}
	if jsonCount != limit-1 {
		t.Fatalf("after prune at limit retained %d, want %d (room for next write)", jsonCount, limit-1)
	}
	store := Store{Root: root}
	base := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
	report := fixtureReport(base, "pruned-check", []string{"Stripe"})
	report.Results[0].Domain = "example.com"
	report.Results[0].Status = agentapi.StatusOK
	if _, err := store.Save(report, "v1", testDigest); err != nil {
		t.Fatalf("Save after prune setup failed: %v", err)
	}
	items, err = os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	jsonCount = 0
	for _, item := range items {
		if item.Type().IsRegular() && strings.HasSuffix(item.Name(), ".json") {
			jsonCount++
		}
	}
	if jsonCount != limit {
		t.Fatalf("after Save retained %d, want %d", jsonCount, limit)
	}
	if _, err := os.Stat(filepath.Join(directory, "20260102T100000.000000000Z-aaaa-0000.json")); !os.IsNotExist(err) {
		t.Fatalf("expected oldest entry pruned, err=%v", err)
	}
	if _, err := store.History("example.com", limit); err != nil {
		t.Fatalf("History after prune should remain readable: %v", err)
	}
	if _, err := store.Latest("example.com"); err != nil {
		t.Fatalf("Latest after prune failed: %v", err)
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
