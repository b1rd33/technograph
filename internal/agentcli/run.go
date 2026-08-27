package agentcli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/b1rd33/technograph/internal/agentapi"
	"github.com/b1rd33/technograph/internal/app"
	"github.com/b1rd33/technograph/internal/fingerprint"
	"github.com/b1rd33/technograph/internal/output"
)

// Run executes one structured subcommand.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, bundledFingerprints []byte) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "scan":
		return runScan(ctx, args[1:], stdin, stdout, stderr, bundledFingerprints)
	case "validate":
		return runValidate(args[1:], stdin, stdout, stderr)
	case "fingerprints":
		return runFingerprints(args[1:], stdout, stderr, bundledFingerprints)
	case "compare":
		return runCompare(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "technograph: unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(writer io.Writer) {
	fmt.Fprintln(writer, `Usage:
  technograph [legacy flags] domains.txt
  technograph scan [flags] [domain ...]
  technograph validate [flags] [domain ...]
  technograph fingerprints [flags]
  technograph compare [flags] before.json after.json

Structured commands accept flags before or after domain arguments. When no
domains are provided, scan and validate read one domain per line from stdin.`)
}

type scanFlags struct {
	format          string
	input           string
	output          string
	fingerprints    string
	requestID       string
	concurrency     int
	httpTimeout     time.Duration
	dnsTimeout      time.Duration
	evidence        bool
	verbose         bool
	allowPrivateNet bool
}

func runScan(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, bundled []byte) int {
	flags := flag.NewFlagSet("technograph scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	config := scanFlags{}
	flags.StringVar(&config.format, "format", "json", "output format: json or jsonl")
	flags.StringVar(&config.input, "input", "", "domain file path, or - for stdin")
	flags.StringVar(&config.output, "output", "", "output path (default stdout)")
	flags.StringVar(&config.fingerprints, "fingerprints", "", "external normalized fingerprint JSON")
	flags.StringVar(&config.requestID, "request-id", "", "caller-provided request correlation ID")
	flags.IntVar(&config.concurrency, "concurrency", 10, "maximum domains scanned concurrently")
	flags.DurationVar(&config.httpTimeout, "timeout", 8*time.Second, "HTTP timeout per domain")
	flags.DurationVar(&config.dnsTimeout, "dns-timeout", 3*time.Second, "timeout per DNS record query")
	flags.BoolVar(&config.evidence, "evidence", true, "include matching evidence")
	flags.BoolVar(&config.verbose, "verbose", false, "enable verbose diagnostics on stderr")
	flags.BoolVar(&config.allowPrivateNet, "allow-private-network", false, "disable autonomous SSRF protection for this local invocation")
	normalized, err := intersperse(args, map[string]bool{
		"format": true, "input": true, "output": true, "fingerprints": true,
		"request-id": true, "concurrency": true, "timeout": true, "dns-timeout": true,
		"evidence": false, "verbose": false, "allow-private-network": false,
	})
	if err != nil || flags.Parse(normalized) != nil {
		if err != nil {
			fmt.Fprintf(stderr, "technograph: %v\n", err)
		}
		return 2
	}
	if config.format != "json" && config.format != "jsonl" {
		fmt.Fprintln(stderr, "technograph: format must be json or jsonl")
		return 2
	}
	if config.concurrency < 1 || config.httpTimeout <= 0 || config.dnsTimeout <= 0 {
		fmt.Fprintln(stderr, "technograph: concurrency and timeouts must be positive")
		return 2
	}
	inputs, err := collectInputs(flags.Args(), config.input, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "technograph: %v\n", err)
		return 1
	}
	fingerprintData, strict, err := loadFingerprintData(config.fingerprints, bundled)
	if err != nil {
		fmt.Fprintf(stderr, "technograph: %v\n", err)
		return 1
	}
	level := slog.LevelWarn
	if config.verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
	service, warnings, err := app.New(app.Options{
		FingerprintData: fingerprintData, StrictFingerprints: strict,
		Concurrency: config.concurrency, HTTPTimeout: config.httpTimeout, DNSTimeout: config.dnsTimeout,
		DomainTimeout: max(config.httpTimeout, config.dnsTimeout) + time.Second,
		SafeNetwork:   !config.allowPrivateNet, Logger: logger,
	})
	if err != nil {
		fmt.Fprintf(stderr, "technograph: %v\n", err)
		return 1
	}
	defer service.Close()
	for _, warning := range warnings {
		fmt.Fprintf(stderr, "technograph: warning: %v\n", warning)
	}
	runner := agentapi.Runner{Service: service, MaxDomains: agentapi.DefaultMaxDomains}
	if config.format == "jsonl" {
		return writeJSONL(ctx, runner, inputs, config, stdout, stderr)
	}
	report, err := runner.Scan(ctx, config.requestID, inputs)
	if err != nil {
		fmt.Fprintf(stderr, "technograph: %v\n", err)
		return 1
	}
	if !config.evidence {
		stripEvidence(report.Results)
	}
	return writeValue(report, config.output, stdout, stderr)
}

func writeJSONL(ctx context.Context, runner agentapi.Runner, inputs []string, config scanFlags, stdout, stderr io.Writer) int {
	requestID, stream, err := runner.ScanStream(ctx, config.requestID, inputs)
	if err != nil {
		fmt.Fprintf(stderr, "technograph: %v\n", err)
		return 1
	}
	var buffer bytes.Buffer
	writer := stdout
	if config.output != "" && config.output != "-" {
		writer = &buffer
	}
	encoder := json.NewEncoder(writer)
	startedAt := time.Now().UTC()
	started := agentapi.JSONLRecord{Type: "scan_started", SchemaVersion: agentapi.SchemaVersion, RequestID: requestID, GeneratedAt: &startedAt}
	if err := encoder.Encode(started); err != nil {
		fmt.Fprintf(stderr, "technograph: encode output: %v\n", err)
		return 1
	}
	results := make([]agentapi.DomainResult, 0, len(inputs))
	for result := range stream {
		if !config.evidence {
			result.Evidence = nil
		}
		results = append(results, result)
		record := agentapi.JSONLRecord{Type: "domain_result", SchemaVersion: agentapi.SchemaVersion, RequestID: requestID, Result: &result}
		if err := encoder.Encode(record); err != nil {
			fmt.Fprintf(stderr, "technograph: encode output: %v\n", err)
			return 1
		}
	}
	summary := summarizeForCLI(results)
	completedAt := time.Now().UTC()
	completed := agentapi.JSONLRecord{Type: "scan_completed", SchemaVersion: agentapi.SchemaVersion, RequestID: requestID, GeneratedAt: &completedAt, Summary: &summary}
	if err := encoder.Encode(completed); err != nil {
		fmt.Fprintf(stderr, "technograph: encode output: %v\n", err)
		return 1
	}
	if config.output != "" && config.output != "-" {
		return writeBytes(buffer.Bytes(), config.output, stdout, stderr)
	}
	return 0
}

func runValidate(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("technograph validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("input", "", "domain file path, or - for stdin")
	outputPath := flags.String("output", "", "output path (default stdout)")
	normalized, err := intersperse(args, map[string]bool{"input": true, "output": true})
	if err != nil || flags.Parse(normalized) != nil {
		if err != nil {
			fmt.Fprintf(stderr, "technograph: %v\n", err)
		}
		return 2
	}
	inputs, err := collectInputs(flags.Args(), *input, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "technograph: %v\n", err)
		return 1
	}
	results, err := (agentapi.Runner{MaxDomains: agentapi.DefaultMaxDomains}).Validate(inputs)
	if err != nil {
		fmt.Fprintf(stderr, "technograph: %v\n", err)
		return 1
	}
	value := struct {
		SchemaVersion string                  `json:"schema_version"`
		Results       []agentapi.DomainResult `json:"results"`
	}{agentapi.SchemaVersion, results}
	return writeValue(value, *outputPath, stdout, stderr)
}

func runFingerprints(args []string, stdout, stderr io.Writer, bundled []byte) int {
	flags := flag.NewFlagSet("technograph fingerprints", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("fingerprints", "", "external normalized fingerprint JSON")
	outputPath := flags.String("output", "", "output path (default stdout)")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return 2
	}
	data, strict, err := loadFingerprintData(*path, bundled)
	if err != nil {
		fmt.Fprintf(stderr, "technograph: %v\n", err)
		return 1
	}
	database, warnings, err := fingerprint.Load(data, strict)
	if err != nil {
		fmt.Fprintf(stderr, "technograph: %v\n", err)
		return 1
	}
	for _, warning := range warnings {
		fmt.Fprintf(stderr, "technograph: warning: %v\n", warning)
	}
	descriptors := database.Descriptors()
	return writeValue(agentapi.FingerprintInventory{
		SchemaVersion: agentapi.SchemaVersion, Count: len(descriptors), Fingerprints: descriptors,
	}, *outputPath, stdout, stderr)
}

func runCompare(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("technograph compare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	outputPath := flags.String("output", "", "output path (default stdout)")
	normalized, err := intersperse(args, map[string]bool{"output": true})
	if err != nil || flags.Parse(normalized) != nil {
		if err != nil {
			fmt.Fprintf(stderr, "technograph: %v\n", err)
		}
		return 2
	}
	if flags.NArg() != 2 {
		fmt.Fprintln(stderr, "Usage: technograph compare [--output path] before.json after.json")
		return 2
	}
	before, err := readReport(flags.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "technograph: %v\n", err)
		return 1
	}
	after, err := readReport(flags.Arg(1))
	if err != nil {
		fmt.Fprintf(stderr, "technograph: %v\n", err)
		return 1
	}
	return writeValue(agentapi.Diff(before, after, time.Now()), *outputPath, stdout, stderr)
}

func collectInputs(arguments []string, inputPath string, stdin io.Reader) ([]string, error) {
	if inputPath != "" && len(arguments) > 0 {
		return nil, errors.New("use either positional domains or --input, not both")
	}
	if inputPath == "" && len(arguments) > 0 {
		return append([]string(nil), arguments...), nil
	}
	reader := stdin
	source := "stdin"
	if inputPath != "" && inputPath != "-" {
		file, err := os.Open(inputPath)
		if err != nil {
			return nil, fmt.Errorf("open input %s: %w", inputPath, err)
		}
		defer file.Close()
		reader = file
		source = inputPath
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024), 4096)
	inputs := make([]string, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "\ufeff"))
		if line != "" && !strings.HasPrefix(line, "#") {
			inputs = append(inputs, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", source, err)
	}
	if len(inputs) == 0 {
		return nil, fmt.Errorf("%s: no domains found", source)
	}
	return inputs, nil
}

func intersperse(args []string, known map[string]bool) ([]string, error) {
	options := make([]string, 0, len(args))
	positionals := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "--" {
			positionals = append(positionals, args[index+1:]...)
			break
		}
		if !strings.HasPrefix(argument, "-") || argument == "-" {
			positionals = append(positionals, argument)
			continue
		}
		nameValue := strings.TrimLeft(argument, "-")
		name, _, inline := strings.Cut(nameValue, "=")
		requiresValue, ok := known[name]
		if !ok {
			return nil, fmt.Errorf("unknown flag %q", argument)
		}
		options = append(options, argument)
		if requiresValue && !inline {
			if index+1 >= len(args) {
				return nil, fmt.Errorf("flag %q requires a value", argument)
			}
			index++
			options = append(options, args[index])
		}
	}
	return append(options, positionals...), nil
}

func loadFingerprintData(path string, bundled []byte) ([]byte, bool, error) {
	if path == "" {
		return bundled, true, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read fingerprints: %w", err)
	}
	return data, false, nil
}

func readReport(path string) (agentapi.Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return agentapi.Report{}, fmt.Errorf("read snapshot %s: %w", path, err)
	}
	var report agentapi.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return agentapi.Report{}, fmt.Errorf("decode snapshot %s: %w", path, err)
	}
	if report.SchemaVersion != agentapi.SchemaVersion {
		return agentapi.Report{}, fmt.Errorf("snapshot %s has unsupported schema version %q", path, report.SchemaVersion)
	}
	return report, nil
}

func writeValue(value any, path string, stdout, stderr io.Writer) int {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "technograph: encode output: %v\n", err)
		return 1
	}
	return writeBytes(append(data, '\n'), path, stdout, stderr)
}

func writeBytes(data []byte, path string, stdout, stderr io.Writer) int {
	if path != "" && path != "-" {
		if err := output.WriteAtomic(path, data); err != nil {
			fmt.Fprintf(stderr, "technograph: %v\n", err)
			return 1
		}
		return 0
	}
	if _, err := stdout.Write(data); err != nil {
		fmt.Fprintf(stderr, "technograph: write stdout: %v\n", err)
		return 1
	}
	return 0
}

func stripEvidence(results []agentapi.DomainResult) {
	for index := range results {
		results[index].Evidence = nil
	}
}

func summarizeForCLI(results []agentapi.DomainResult) agentapi.Summary {
	summary := agentapi.Summary{Requested: len(results)}
	for _, result := range results {
		summary.Detections += len(result.Technologies)
		switch result.Status {
		case agentapi.StatusOK:
			summary.OK++
		case agentapi.StatusPartial:
			summary.Partial++
		case agentapi.StatusBlocked:
			summary.Blocked++
		case agentapi.StatusFailed:
			summary.Failed++
		case agentapi.StatusInvalid:
			summary.Invalid++
		}
	}
	return summary
}
