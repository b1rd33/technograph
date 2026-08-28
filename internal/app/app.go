package app

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"time"

	"github.com/b1rd33/technograph/internal/fingerprint"
	"github.com/b1rd33/technograph/internal/model"
	"github.com/b1rd33/technograph/internal/probe"
	"github.com/b1rd33/technograph/internal/scanner"
)

const (
	defaultConcurrency = 10
	defaultHTTPTimeout = 8 * time.Second
	defaultDNSTimeout  = 3 * time.Second
)

// Options configures one reusable scanning service.
type Options struct {
	FingerprintData    []byte
	StrictFingerprints bool
	Concurrency        int
	HTTPTimeout        time.Duration
	DNSTimeout         time.Duration
	DNSServers         []string
	DomainTimeout      time.Duration
	PageLimit          int
	InsecureTLS        bool
	SafeNetwork        bool
	Logger             *slog.Logger

	// HTTP and DNS are optional test and integration seams. Production callers
	// normally leave them nil and use the bounded system probes.
	HTTP scanner.HTTPProber
	DNS  scanner.DNSProber
}

// Service owns the reusable resources needed to execute scans.
type Service struct {
	scanner           scanner.Scanner
	database          *fingerprint.Database
	fingerprintDigest string
	close             func()
}

// New validates configuration, compiles fingerprints, and constructs a
// reusable scanner. Unsupported external patterns are returned as warnings.
func New(options Options) (*Service, []fingerprint.Warning, error) {
	database, warnings, err := fingerprint.Load(options.FingerprintData, options.StrictFingerprints)
	if err != nil {
		return nil, nil, err
	}
	if options.HTTPTimeout <= 0 {
		options.HTTPTimeout = defaultHTTPTimeout
	}
	if options.DNSTimeout <= 0 {
		options.DNSTimeout = defaultDNSTimeout
	}

	httpProber := options.HTTP
	closeHTTP := func() {}
	if httpProber == nil {
		configured := probe.NewHTTPProbe(probe.HTTPOptions{
			Timeout: options.HTTPTimeout, InsecureTLS: options.InsecureTLS,
			SafeNetwork: options.SafeNetwork, PageLimit: options.PageLimit, Logger: options.Logger,
		})
		httpProber = configured
		closeHTTP = configured.CloseIdleConnections
	}

	dnsProber := options.DNS
	if dnsProber == nil {
		if len(options.DNSServers) > 0 {
			var servers []string
			servers, err = probe.NormalizeDNSServers(options.DNSServers)
			if err == nil {
				dnsProber, err = probe.NewDNSProbe(probe.DNSOptions{Servers: servers, Timeout: options.DNSTimeout, Logger: options.Logger})
			}
		} else {
			dnsProber, err = probe.NewSystemDNSProbe(options.DNSTimeout, options.Logger)
		}
		if err != nil {
			closeHTTP()
			return nil, warnings, fmt.Errorf("configure DNS probe: %w", err)
		}
	}

	concurrency := options.Concurrency
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}
	domainTimeout := options.DomainTimeout
	if domainTimeout <= 0 {
		domainTimeout = max(options.HTTPTimeout, options.DNSTimeout) + time.Second
	}

	return &Service{
		scanner: scanner.Scanner{
			HTTP: httpProber, DNS: dnsProber, Engine: fingerprint.NewEngine(database),
			Concurrency: concurrency, Timeout: domainTimeout,
		},
		database:          database,
		fingerprintDigest: fmt.Sprintf("sha256:%x", sha256.Sum256(options.FingerprintData)),
		close:             closeHTTP,
	}, warnings, nil
}

// FingerprintDigest identifies the exact source database used by this service.
func (service *Service) FingerprintDigest() string { return service.fingerprintDigest }

// Fingerprints returns the compiled fingerprint inventory.
func (service *Service) Fingerprints() []fingerprint.Descriptor {
	return service.database.Descriptors()
}

// CategoriesFor returns category metadata for detected technologies.
func (service *Service) CategoriesFor(technologies []string) map[string][]string {
	output := make(map[string][]string)
	for _, technology := range technologies {
		if categories := service.database.Categories(technology); len(categories) > 0 {
			output[technology] = categories
		}
	}
	return output
}

// Scan processes validated domains while preserving their input order.
func (service *Service) Scan(ctx context.Context, domains []model.Domain) []model.ScanResult {
	return service.scanner.Scan(ctx, domains)
}

// ScanStream emits results in completion order for JSONL and protocol clients.
func (service *Service) ScanStream(ctx context.Context, domains []model.Domain) <-chan scanner.IndexedResult {
	return service.scanner.ScanStream(ctx, domains)
}

// Close releases idle network resources owned by the service.
func (service *Service) Close() {
	service.close()
}
