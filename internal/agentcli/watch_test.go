package agentcli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/b1rd33/technograph/internal/agentapi"
	"github.com/b1rd33/technograph/internal/history"
)

const (
	watchDigestOne = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	watchDigestTwo = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

func TestCompareWithHistoryBaselinesAndConservativeChanges(t *testing.T) {
	t.Parallel()
	store := history.Store{Root: t.TempDir()}
	first := watchFixture(time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC), "first", agentapi.StatusOK, []string{"Stripe"})
	changes, baselines, err := compareWithHistory(store, first, "v1", watchDigestOne)
	if err != nil || len(changes.Changes) != 0 || len(baselines) != 1 || baselines[0].Reason != "first_observation" {
		t.Fatalf("changes=%#v baselines=%#v error=%v", changes, baselines, err)
	}
	if _, err := store.Save(first, "v1", watchDigestOne); err != nil {
		t.Fatal(err)
	}

	second := watchFixture(time.Date(2026, 8, 28, 11, 0, 0, 0, time.UTC), "second", agentapi.StatusOK, []string{"Stripe", "Cloudflare"})
	changes, baselines, err = compareWithHistory(store, second, "v1", watchDigestOne)
	if err != nil || len(baselines) != 0 || len(changes.Changes) != 1 || changes.Changes[0].Technology != "Cloudflare" || changes.Changes[0].Kind != agentapi.ChangeAdded {
		t.Fatalf("changes=%#v baselines=%#v error=%v", changes, baselines, err)
	}

	blocked := watchFixture(time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC), "blocked", agentapi.StatusBlocked, []string{})
	changes, _, err = compareWithHistory(store, blocked, "v1", watchDigestOne)
	if err != nil || len(changes.Changes) != 0 || len(changes.Uncertain) != 1 {
		t.Fatalf("blocked changes=%#v error=%v", changes, err)
	}

	changes, baselines, err = compareWithHistory(store, second, "v1", watchDigestTwo)
	if err != nil || len(changes.Changes) != 0 || len(baselines) != 1 || baselines[0].Reason != "fingerprint_changed" {
		t.Fatalf("digest changes=%#v baselines=%#v error=%v", changes, baselines, err)
	}
	changes, baselines, err = compareWithHistory(store, second, "v2", watchDigestOne)
	if err != nil || len(changes.Changes) != 0 || len(baselines) != 1 || baselines[0].Reason != "scanner_changed" {
		t.Fatalf("version changes=%#v baselines=%#v error=%v", changes, baselines, err)
	}
}

func TestHistoryCommandReadsStoreWithoutNetwork(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	store := history.Store{Root: root}
	report := watchFixture(time.Now(), "saved", agentapi.StatusOK, []string{"Stripe"})
	if _, err := store.Save(report, "v1", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"history", "example.com", "--store", root}, strings.NewReader(""), &stdout, &stderr, nil)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	var decoded history.Report
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil || len(decoded.Entries) != 1 || decoded.Entries[0].RequestID != "saved" {
		t.Fatalf("decoded=%#v error=%v", decoded, err)
	}
}

func watchFixture(at time.Time, requestID string, status agentapi.Status, technologies []string) agentapi.Report {
	return agentapi.Report{
		SchemaVersion: agentapi.SchemaVersion, RequestID: requestID, GeneratedAt: at,
		Results: []agentapi.DomainResult{{
			InputIndex: 0, Input: "example.com", Domain: "example.com", Apex: "example.com",
			Status: status, Technologies: technologies, Warnings: []agentapi.Issue{}, Errors: []agentapi.Issue{},
		}},
	}
}
