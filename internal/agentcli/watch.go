package agentcli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/b1rd33/technograph/internal/agentapi"
	"github.com/b1rd33/technograph/internal/buildinfo"
	"github.com/b1rd33/technograph/internal/domain"
	"github.com/b1rd33/technograph/internal/history"
)

func runWatch(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, bundled []byte) int {
	flags := flag.NewFlagSet("technograph watch", flag.ContinueOnError)
	flags.SetOutput(stderr)
	config := scanFlags{}
	storePath := flags.String("store", "", "local immutable history directory (required)")
	flags.StringVar(&config.input, "input", "", "domain file path, or - for stdin")
	flags.StringVar(&config.output, "output", "", "watch report path (default stdout)")
	flags.StringVar(&config.fingerprints, "fingerprints", "", "external normalized fingerprint JSON")
	flags.StringVar(&config.requestID, "request-id", "", "caller-provided request correlation ID")
	flags.IntVar(&config.concurrency, "concurrency", 10, "maximum domains scanned concurrently")
	flags.DurationVar(&config.httpTimeout, "timeout", 8*time.Second, "HTTP timeout per domain")
	flags.DurationVar(&config.dnsTimeout, "dns-timeout", 3*time.Second, "timeout per DNS record query")
	flags.IntVar(&config.pageLimit, "pages", 1, "maximum same-host HTML pages per domain (1-5)")
	flags.Var(&config.dnsServers, "dns-server", "custom DNS resolver IP[:port] (repeatable)")
	flags.BoolVar(&config.evidence, "evidence", true, "include matching evidence in stored observations")
	flags.BoolVar(&config.verbose, "verbose", false, "enable verbose diagnostics on stderr")
	flags.BoolVar(&config.allowPrivateNet, "allow-private-network", false, "disable autonomous SSRF protection for this local invocation")
	failOnChange := flags.Bool("fail-on-change", false, "exit with status 3 after writing a report containing confirmed changes")
	if wantsHelp(args) {
		subcommandUsage(stdout, "technograph watch [flags] [domain ...]", flags,
			`Runs one normal scan, compares it with each domain's latest compatible local
observation, and stores the new immutable observation. First observations and
scanner/fingerprint changes establish a new baseline instead of emitting false
technology changes. Per-domain partial or blocked scans suppress removals.

Examples:
  technograph watch stripe.com --store .technograph-history
  technograph watch stripe.com --pages 3 --store .technograph-history
  technograph watch --input domains.txt --store /absolute/history --output watch.json
  technograph watch stripe.com --store .technograph-history --fail-on-change`)
		return 0
	}
	normalized, err := intersperse(args, map[string]bool{
		"store": true, "input": true, "output": true, "fingerprints": true,
		"request-id": true, "concurrency": true, "timeout": true, "dns-timeout": true,
		"dns-server": true, "pages": true, "evidence": false, "verbose": false,
		"allow-private-network": false, "fail-on-change": false,
	})
	if err != nil || flags.Parse(normalized) != nil {
		if err != nil {
			fmt.Fprintf(stderr, "technograph: %v\n", err)
		}
		return 2
	}
	if *storePath == "" {
		fmt.Fprintln(stderr, "technograph: --store is required")
		return 2
	}
	if config.concurrency < 1 || config.httpTimeout <= 0 || config.dnsTimeout <= 0 {
		fmt.Fprintln(stderr, "technograph: concurrency and timeouts must be positive")
		return 2
	}
	if config.pageLimit < 1 || config.pageLimit > 5 {
		fmt.Fprintln(stderr, "technograph: pages must be between 1 and 5")
		return 2
	}
	inputs, err := collectInputs(flags.Args(), config.input, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "technograph: %v\n", err)
		return 1
	}
	service, err := newScanService(config, bundled, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "technograph: %v\n", err)
		return 1
	}
	defer service.Close()
	report, err := (agentapi.Runner{Service: service, MaxDomains: agentapi.DefaultMaxDomains}).Scan(ctx, config.requestID, inputs)
	if err != nil {
		fmt.Fprintf(stderr, "technograph: %v\n", err)
		return 1
	}
	if !config.evidence {
		stripEvidence(report.Results)
	}
	store := history.Store{Root: *storePath}
	// Page coverage changes what can be observed, so include it in history's
	// compatibility identity and establish a baseline when callers change it.
	version := fmt.Sprintf("%s;pages=%d", buildinfo.Identity(), config.pageLimit)
	digest := service.FingerprintDigest()
	watchReport, err := history.Observe(store, report, version, digest)
	if err != nil {
		fmt.Fprintf(stderr, "technograph: watch history: %v\n", err)
		return 1
	}
	if code := writeValue(watchReport, config.output, stdout, stderr); code != 0 {
		return code
	}
	if *failOnChange && len(watchReport.Changes.Changes) > 0 {
		return 3
	}
	return 0
}

func compareWithHistory(store history.Store, report agentapi.Report, version, digest string) (agentapi.DiffReport, []history.Baseline, error) {
	return history.Compare(store, report, version, digest)
}

func runHistory(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("technograph history", flag.ContinueOnError)
	flags.SetOutput(stderr)
	storePath := flags.String("store", "", "local immutable history directory (required)")
	limit := flags.Int("limit", 20, "maximum newest observations to return")
	outputPath := flags.String("output", "", "output path (default stdout)")
	if wantsHelp(args) {
		subcommandUsage(stdout, "technograph history [flags] domain", flags,
			`Reads newest-first local observations without making network requests.
History entries include scanner and fingerprint identities so automation can
audit why a watch baseline was reset.

Examples:
  technograph history stripe.com --store .technograph-history
  technograph history stripe.com --store .technograph-history --limit 5 --output history.json`)
		return 0
	}
	normalized, err := intersperse(args, map[string]bool{"store": true, "limit": true, "output": true})
	if err != nil || flags.Parse(normalized) != nil {
		if err != nil {
			fmt.Fprintf(stderr, "technograph: %v\n", err)
		}
		return 2
	}
	if *storePath == "" || flags.NArg() != 1 {
		fmt.Fprintln(stderr, "Usage: technograph history --store path [--limit N] domain")
		return 2
	}
	if *limit < 1 || *limit > history.MaximumEntries {
		fmt.Fprintf(stderr, "technograph: --limit must be between 1 and %d\n", history.MaximumEntries)
		return 2
	}
	parsed, err := domain.Parse(flags.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "technograph: invalid domain: %v\n", err)
		return 2
	}
	report, err := (history.Store{Root: *storePath}).History(parsed.Hostname, *limit)
	if err != nil {
		fmt.Fprintf(stderr, "technograph: history: %v\n", err)
		return 1
	}
	return writeValue(report, *outputPath, stdout, stderr)
}
