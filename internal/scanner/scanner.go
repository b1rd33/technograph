// Package scanner coordinates bounded concurrent domain scans.
package scanner

import (
	"context"
	"sync"
	"time"

	"github.com/b1rd33/technograph/internal/fingerprint"
	"github.com/b1rd33/technograph/internal/model"
)

type HTTPProber interface {
	Probe(context.Context, string) (model.HTTPResult, []model.Signal)
}

type DNSProber interface {
	Probe(context.Context, string) (model.DNSResult, []model.Signal)
}

type Scanner struct {
	HTTP        HTTPProber
	DNS         DNSProber
	Engine      *fingerprint.Engine
	Concurrency int
	Timeout     time.Duration
}

// IndexedResult associates a completed result with its input position.
type IndexedResult struct {
	Index  int
	Result model.ScanResult
}

// Scan processes all domains with a bounded worker pool and preserves input order.
func (scanner Scanner) Scan(ctx context.Context, domains []model.Domain) []model.ScanResult {
	results := make([]model.ScanResult, len(domains))
	for completed := range scanner.ScanStream(ctx, domains) {
		results[completed.Index] = completed.Result
	}
	return results
}

// ScanStream emits results in completion order. The channel is buffered for
// the whole bounded request so cancellation by a consumer cannot leak workers.
func (scanner Scanner) ScanStream(ctx context.Context, domains []model.Domain) <-chan IndexedResult {
	completed := make(chan IndexedResult, len(domains))
	workers := scanner.Concurrency
	if workers <= 0 {
		workers = 10
	}
	if workers > len(domains) {
		workers = len(domains)
	}
	go func() {
		defer close(completed)
		if workers == 0 {
			return
		}
		jobs := make(chan int)
		var group sync.WaitGroup
		group.Add(workers)
		for range workers {
			go func() {
				defer group.Done()
				for index := range jobs {
					completed <- IndexedResult{Index: index, Result: scanner.scanOne(ctx, domains[index])}
				}
			}()
		}
		for index := range domains {
			jobs <- index
		}
		close(jobs)
		group.Wait()
	}()
	return completed
}

func (scanner Scanner) scanOne(parent context.Context, domain model.Domain) model.ScanResult {
	started := time.Now()
	ctx := parent
	cancel := func() {}
	if scanner.Timeout > 0 {
		ctx, cancel = context.WithTimeout(parent, scanner.Timeout)
	}
	defer cancel()

	type httpOutcome struct {
		result  model.HTTPResult
		signals []model.Signal
	}
	type dnsOutcome struct {
		result  model.DNSResult
		signals []model.Signal
	}
	httpDone := make(chan httpOutcome, 1)
	dnsDone := make(chan dnsOutcome, 1)
	go func() {
		result, signals := scanner.HTTP.Probe(ctx, domain.Hostname)
		httpDone <- httpOutcome{result, signals}
	}()
	go func() { result, signals := scanner.DNS.Probe(ctx, domain.Apex); dnsDone <- dnsOutcome{result, signals} }()
	httpResult := <-httpDone
	dnsResult := <-dnsDone
	signals := append(httpResult.signals, dnsResult.signals...)
	technologies, evidence := scanner.Engine.Detect(signals)
	elapsed := time.Since(started)
	return model.ScanResult{
		Domain: domain, Technologies: technologies, Evidence: evidence,
		HTTP: httpResult.result, DNS: dnsResult.result,
		Elapsed: elapsed, ElapsedMS: elapsed.Milliseconds(),
	}
}
