// Package history stores immutable local scan observations without a daemon or
// external database. Domain directories are hashed to avoid path traversal.
package history

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/b1rd33/technograph/internal/agentapi"
)

const (
	SchemaVersion    = "1.0"
	maximumEntrySize = 16 << 20
	MaximumEntries   = 10000
)

var ErrNoHistory = errors.New("no history found")

type Entry struct {
	SchemaVersion     string                `json:"schema_version"`
	ID                string                `json:"id"`
	RecordedAt        time.Time             `json:"recorded_at"`
	RequestID         string                `json:"request_id"`
	ScannerVersion    string                `json:"scanner_version"`
	FingerprintDigest string                `json:"fingerprint_digest"`
	Result            agentapi.DomainResult `json:"result"`
}

type Report struct {
	SchemaVersion string  `json:"schema_version"`
	Domain        string  `json:"domain"`
	Entries       []Entry `json:"entries"`
}

type Baseline struct {
	Domain string `json:"domain"`
	Reason string `json:"reason"`
}

type StoredRef struct {
	Domain     string    `json:"domain"`
	ID         string    `json:"id"`
	RecordedAt time.Time `json:"recorded_at"`
}

type WatchReport struct {
	SchemaVersion string              `json:"schema_version"`
	GeneratedAt   time.Time           `json:"generated_at"`
	Scan          agentapi.Report     `json:"scan"`
	Changes       agentapi.DiffReport `json:"changes"`
	Baselines     []Baseline          `json:"baselines"`
	Stored        []StoredRef         `json:"stored"`
}

type Store struct {
	Root string
	Now  func() time.Time
}

// Compare returns only changes from observations made with the same scanner
// and fingerprint identities. Incompatible or first observations establish a
// baseline instead of manufacturing technology changes.
func Compare(store Store, report agentapi.Report, scannerVersion, fingerprintDigest string) (agentapi.DiffReport, []Baseline, error) {
	before := agentapi.Report{SchemaVersion: agentapi.SchemaVersion, Results: []agentapi.DomainResult{}}
	comparableAfter := agentapi.Report{SchemaVersion: agentapi.SchemaVersion, RequestID: report.RequestID, GeneratedAt: report.GeneratedAt, Results: []agentapi.DomainResult{}}
	baselines := make([]Baseline, 0)
	for _, result := range report.Results {
		if result.Domain == "" || result.Status == agentapi.StatusInvalid {
			continue
		}
		previous, err := store.Latest(result.Domain)
		switch {
		case errors.Is(err, ErrNoHistory):
			baselines = append(baselines, Baseline{Domain: result.Domain, Reason: "first_observation"})
		case err != nil:
			return agentapi.DiffReport{}, nil, fmt.Errorf("load %s: %w", result.Domain, err)
		case previous.FingerprintDigest != fingerprintDigest:
			baselines = append(baselines, Baseline{Domain: result.Domain, Reason: "fingerprint_changed"})
		case previous.ScannerVersion != scannerVersion:
			baselines = append(baselines, Baseline{Domain: result.Domain, Reason: "scanner_changed"})
		default:
			before.Results = append(before.Results, previous.Result)
			comparableAfter.Results = append(comparableAfter.Results, result)
		}
	}
	changes := agentapi.Diff(before, comparableAfter, report.GeneratedAt)
	sort.Slice(baselines, func(i, j int) bool { return baselines[i].Domain < baselines[j].Domain })
	return changes, baselines, nil
}

// Observe compares a completed scan to compatible history, then stores it as
// an immutable observation. Comparison completes before any write occurs.
func Observe(store Store, report agentapi.Report, scannerVersion, fingerprintDigest string) (WatchReport, error) {
	changes, baselines, err := Compare(store, report, scannerVersion, fingerprintDigest)
	if err != nil {
		return WatchReport{}, err
	}
	stored, err := store.Save(report, scannerVersion, fingerprintDigest)
	if err != nil {
		return WatchReport{}, err
	}
	references := make([]StoredRef, 0, len(stored))
	for _, entry := range stored {
		references = append(references, StoredRef{Domain: entry.Result.Domain, ID: entry.ID, RecordedAt: entry.RecordedAt})
	}
	return WatchReport{
		SchemaVersion: SchemaVersion, GeneratedAt: report.GeneratedAt,
		Scan: report, Changes: changes, Baselines: baselines, Stored: references,
	}, nil
}

func (store Store) Save(report agentapi.Report, scannerVersion, fingerprintDigest string) ([]Entry, error) {
	if report.RequestID == "" || strings.TrimSpace(scannerVersion) == "" || !validDigest(fingerprintDigest) {
		return nil, errors.New("history metadata is incomplete")
	}
	root, err := store.prepareRoot()
	if err != nil {
		return nil, err
	}
	recordedAt := report.GeneratedAt.UTC()
	if recordedAt.IsZero() {
		recordedAt = store.now()
	}
	entries := make([]Entry, 0, len(report.Results))
	for _, result := range report.Results {
		if result.Domain == "" || result.Status == agentapi.StatusInvalid {
			continue
		}
		id := entryID(recordedAt, report.RequestID, result.InputIndex)
		entry := Entry{
			SchemaVersion: SchemaVersion, ID: id, RecordedAt: recordedAt,
			RequestID: report.RequestID, ScannerVersion: scannerVersion,
			FingerprintDigest: fingerprintDigest, Result: result,
		}
		directory := filepath.Join(root, domainKey(result.Domain))
		if err := ensureDirectory(directory); err != nil {
			return nil, err
		}
		if err := writePrivateAtomic(filepath.Join(directory, id+".json"), entry); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (store Store) Latest(domain string) (Entry, error) {
	entries, err := store.load(domain, 1)
	if err != nil {
		return Entry{}, err
	}
	return entries[0], nil
}

func (store Store) History(domain string, limit int) (Report, error) {
	if limit < 1 || limit > MaximumEntries {
		return Report{}, fmt.Errorf("history limit must be between 1 and %d", MaximumEntries)
	}
	entries, err := store.load(domain, limit)
	if err != nil {
		return Report{}, err
	}
	return Report{SchemaVersion: SchemaVersion, Domain: domain, Entries: entries}, nil
}

func (store Store) load(domain string, limit int) ([]Entry, error) {
	root, err := filepath.Abs(strings.TrimSpace(store.Root))
	if err != nil || strings.TrimSpace(store.Root) == "" {
		return nil, errors.New("history store path is required")
	}
	directory := filepath.Join(root, domainKey(domain))
	items, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoHistory
	}
	if err != nil {
		return nil, fmt.Errorf("read history for %s: %w", domain, err)
	}
	files := make([]string, 0, len(items))
	for _, item := range items {
		if item.Type().IsRegular() && strings.HasSuffix(item.Name(), ".json") {
			files = append(files, item.Name())
		}
	}
	if len(files) == 0 {
		return nil, ErrNoHistory
	}
	if len(files) > MaximumEntries {
		return nil, fmt.Errorf("history for %s exceeds safety limit of %d entries", domain, MaximumEntries)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(files)))
	if len(files) > limit {
		files = files[:limit]
	}
	entries := make([]Entry, 0, len(files))
	for _, name := range files {
		entry, err := readEntry(filepath.Join(directory, name))
		if err != nil {
			return nil, err
		}
		if entry.Result.Domain != domain {
			return nil, fmt.Errorf("history entry %s belongs to unexpected domain %q", name, entry.Result.Domain)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (store Store) prepareRoot() (string, error) {
	if strings.TrimSpace(store.Root) == "" {
		return "", errors.New("history store path is required")
	}
	root, err := filepath.Abs(store.Root)
	if err != nil {
		return "", fmt.Errorf("resolve history store: %w", err)
	}
	if err := ensureDirectory(root); err != nil {
		return "", err
	}
	return root, nil
}

func ensureDirectory(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("history path %s is not a regular directory", path)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect history path %s: %w", path, err)
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create history path %s: %w", path, err)
	}
	return nil
}

func writePrivateAtomic(path string, value any) error {
	directory := filepath.Dir(path)
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("history entry %s already exists", filepath.Base(path))
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect history entry: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".technograph-*.tmp")
	if err != nil {
		return fmt.Errorf("create history temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("protect history temporary file: %w", err)
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("encode history entry: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync history entry: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close history entry: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("commit history entry: %w", err)
	}
	committed = true
	return nil
}

func readEntry(path string) (Entry, error) {
	file, err := os.Open(path)
	if err != nil {
		return Entry{}, fmt.Errorf("open history entry: %w", err)
	}
	defer file.Close()
	reader := io.LimitReader(file, maximumEntrySize+1)
	data, err := io.ReadAll(reader)
	if err != nil {
		return Entry{}, fmt.Errorf("read history entry: %w", err)
	}
	if len(data) > maximumEntrySize {
		return Entry{}, fmt.Errorf("history entry %s exceeds %d bytes", filepath.Base(path), maximumEntrySize)
	}
	var entry Entry
	if err := json.Unmarshal(data, &entry); err != nil {
		return Entry{}, fmt.Errorf("decode history entry %s: %w", filepath.Base(path), err)
	}
	if entry.SchemaVersion != SchemaVersion || entry.ID == "" || entry.Result.Domain == "" {
		return Entry{}, fmt.Errorf("history entry %s has an invalid contract", filepath.Base(path))
	}
	return entry, nil
}

func domainKey(domain string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(domain)))
	return hex.EncodeToString(digest[:])
}

func entryID(recordedAt time.Time, requestID string, inputIndex int) string {
	digest := sha256.Sum256([]byte(requestID))
	return recordedAt.UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(digest[:6]) + fmt.Sprintf("-%04d", inputIndex)
}

func validDigest(value string) bool {
	encoded := strings.TrimPrefix(value, "sha256:")
	if len(encoded) != 64 || encoded == value {
		return false
	}
	_, err := hex.DecodeString(encoded)
	return err == nil
}

func (store Store) now() time.Time {
	if store.Now != nil {
		return store.Now().UTC()
	}
	return time.Now().UTC()
}
