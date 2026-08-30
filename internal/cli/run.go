package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/b1rd33/technograph/internal/app"
	"github.com/b1rd33/technograph/internal/buildinfo"
	"github.com/b1rd33/technograph/internal/output"
)

// Run executes the CLI and returns a process exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, bundledFingerprints []byte) int {
	flags := flag.NewFlagSet("technograph", flag.ContinueOnError)
	flags.SetOutput(stderr)
	outputPath := flags.String("output", "output.json", "required JSON output path")
	concurrency := flags.Int("concurrency", 10, "maximum domains scanned concurrently")
	httpTimeout := flags.Duration("timeout", 8*time.Second, "HTTP timeout per domain")
	dnsTimeout := flags.Duration("dns-timeout", 3*time.Second, "timeout per DNS record query")
	var dnsServers []string
	flags.Func("dns-server", "custom DNS resolver IP[:port] (repeatable)", func(value string) error {
		dnsServers = append(dnsServers, value)
		return nil
	})
	fingerprintPath := flags.String("fingerprints", "", "external normalized fingerprint JSON")
	reportPath := flags.String("report", "", "optional detailed evidence report path")
	insecure := flags.Bool("insecure", false, "disable TLS certificate verification")
	verbose := flags.Bool("verbose", false, "enable verbose diagnostics")
	showVersion := flags.Bool("version", false, "print version information and exit")
	printUsage := func(writer io.Writer) {
		fmt.Fprintln(writer, "Usage: technograph [flags] domains.txt")
		flags.SetOutput(writer)
		flags.PrintDefaults()
	}
	flags.Usage = func() { printUsage(stderr) }
	for _, argument := range args {
		if argument == "--" {
			break
		}
		if argument == "-h" || argument == "--help" {
			printUsage(stdout)
			return 0
		}
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, buildinfo.String())
		return 0
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return 2
	}
	if *concurrency < 1 || *httpTimeout <= 0 || *dnsTimeout <= 0 {
		fmt.Fprintln(stderr, "technograph: concurrency and timeouts must be positive")
		return 2
	}

	// Validate the entire input before constructing any network clients.
	domains, err := LoadDomains(flags.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "technograph: %v\n", err)
		return 1
	}

	fingerprintData := bundledFingerprints
	strict := true
	if *fingerprintPath != "" {
		fingerprintData, err = os.ReadFile(*fingerprintPath)
		if err != nil {
			fmt.Fprintf(stderr, "technograph: read fingerprints: %v\n", err)
			return 1
		}
		strict = false
	}
	level := slog.LevelWarn
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
	service, warnings, err := app.New(legacyAppOptions(fingerprintData, strict, *concurrency, *httpTimeout, *dnsTimeout, dnsServers, *insecure, logger))
	if err != nil {
		fmt.Fprintf(stderr, "technograph: %v\n", err)
		return 1
	}
	defer service.Close()
	for _, warning := range warnings {
		fmt.Fprintf(stderr, "technograph: warning: %v\n", warning)
	}

	started := time.Now()
	results := service.Scan(ctx, domains)
	required, err := output.RequiredJSON(results)
	if err != nil {
		fmt.Fprintf(stderr, "technograph: encode output: %v\n", err)
		return 1
	}
	if err := output.WriteAtomic(*outputPath, required); err != nil {
		fmt.Fprintf(stderr, "technograph: %v\n", err)
		return 1
	}
	if *reportPath != "" {
		report, reportErr := output.ReportJSON(results)
		if reportErr == nil {
			reportErr = output.WriteAtomic(*reportPath, report)
		}
		if reportErr != nil {
			fmt.Fprintf(stderr, "technograph: write report: %v\n", reportErr)
			return 1
		}
	}
	detections, failures, blocked := 0, 0, 0
	for _, result := range results {
		detections += len(result.Technologies)
		if result.HTTP.Error != "" {
			failures++
		}
		if result.HTTP.Blocked {
			blocked++
		}
	}
	fmt.Fprintf(stdout, "Scanned %d domains in %s: %d detections, %d HTTP failures, %d blocked responses\n", len(results), time.Since(started).Round(time.Millisecond), detections, failures, blocked)
	return 0
}

func legacyAppOptions(fingerprintData []byte, strict bool, concurrency int, httpTimeout, dnsTimeout time.Duration, dnsServers []string, insecure bool, logger *slog.Logger) app.Options {
	return app.Options{
		FingerprintData: fingerprintData, StrictFingerprints: strict,
		Concurrency: concurrency, HTTPTimeout: httpTimeout, DNSTimeout: dnsTimeout,
		DNSServers:    dnsServers,
		DomainTimeout: max(httpTimeout, dnsTimeout) + time.Second,
		InsecureTLS:   insecure, SafeNetwork: true, Logger: logger,
	}
}
