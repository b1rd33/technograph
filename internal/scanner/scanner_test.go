package scanner

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/b1rd33/technograph/internal/fingerprint"
	"github.com/b1rd33/technograph/internal/model"
)

type fakeHTTP struct{ active, maximum atomic.Int32 }

func (probe *fakeHTTP) Probe(ctx context.Context, host string) (model.HTTPResult, []model.Signal) {
	current := probe.active.Add(1)
	defer probe.active.Add(-1)
	for maximum := probe.maximum.Load(); current > maximum && !probe.maximum.CompareAndSwap(maximum, current); maximum = probe.maximum.Load() {
	}
	select {
	case <-time.After(15 * time.Millisecond):
	case <-ctx.Done():
	}
	return model.HTTPResult{FinalURL: "https://" + host}, []model.Signal{{Channel: model.ChannelHeader, Name: "cf-ray", Origin: host}}
}

type fakeDNS struct{}

func (fakeDNS) Probe(_ context.Context, apex string) (model.DNSResult, []model.Signal) {
	return model.DNSResult{Apex: apex, MX: []string{}, TXT: []string{}, CNAME: []string{}}, nil
}

func TestScanPreservesOrderAndBoundsConcurrency(t *testing.T) {
	database, _, err := fingerprint.Load([]byte(`{"schema_version":1,"technologies":{"Cloudflare":{"patterns":[{"channel":"header","regex":"cf-ray"}]}}}`), true)
	if err != nil {
		t.Fatal(err)
	}
	httpProbe := &fakeHTTP{}
	domains := []model.Domain{{Hostname: "a.test", Apex: "a.test"}, {Hostname: "b.test", Apex: "b.test"}, {Hostname: "c.test", Apex: "c.test"}, {Hostname: "d.test", Apex: "d.test"}}
	results := (Scanner{HTTP: httpProbe, DNS: fakeDNS{}, Engine: fingerprint.NewEngine(database), Concurrency: 2, Timeout: time.Second}).Scan(context.Background(), domains)
	if httpProbe.maximum.Load() > 2 {
		t.Fatalf("maximum concurrency = %d", httpProbe.maximum.Load())
	}
	for index, result := range results {
		if result.Domain != domains[index] {
			t.Fatalf("result %d out of order", index)
		}
		if len(result.Technologies) != 1 || result.Technologies[0] != "Cloudflare" {
			t.Fatalf("unexpected detection: %v", result.Technologies)
		}
	}
}
