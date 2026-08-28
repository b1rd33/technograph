package agentcli

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/b1rd33/technograph/internal/agentapi"
)

const explorerInputLimit = 64 * 1024

func runExplore(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, bundled []byte) int {
	flags := flag.NewFlagSet("technograph explore", flag.ContinueOnError)
	flags.SetOutput(stderr)
	config := scanFlags{}
	flags.StringVar(&config.input, "input", "", "domain file path (stdin is reserved for explorer commands)")
	flags.StringVar(&config.fingerprints, "fingerprints", "", "external normalized fingerprint JSON")
	flags.IntVar(&config.concurrency, "concurrency", 10, "maximum domains scanned concurrently")
	flags.DurationVar(&config.httpTimeout, "timeout", 8*time.Second, "HTTP timeout per domain")
	flags.DurationVar(&config.dnsTimeout, "dns-timeout", 3*time.Second, "timeout per DNS record query")
	flags.IntVar(&config.pageLimit, "pages", 1, "maximum same-host HTML pages per domain (1-5)")
	flags.Var(&config.dnsServers, "dns-server", "custom DNS resolver IP[:port] (repeatable)")
	flags.BoolVar(&config.verbose, "verbose", false, "enable verbose diagnostics on stderr")
	flags.BoolVar(&config.allowPrivateNet, "allow-private-network", false, "disable autonomous SSRF protection for this local invocation")
	if wantsHelp(args) {
		subcommandUsage(stdout, "technograph explore [flags] [domain ...]", flags,
			`Scans once, then opens a dependency-free interactive evidence explorer.
Use list/filter to navigate and show to inspect the same deterministic report
produced by "explain". This is a local terminal view, not a web dashboard.
Standard input is reserved for explorer commands, so use --input with a file.

Commands:
  list                 List domains matching the active filter
  filter TEXT          Filter by domain, status, technology, or category
  clear                Clear the active filter
  show NUMBER|DOMAIN   Show one domain's complete evidence report
  help                 Show commands
  quit                 Exit

Examples:
  technograph explore stripe.com shopify.com
  technograph explore stripe.com --pages 3
  technograph explore --input domains.txt`)
		return 0
	}
	normalized, err := intersperse(args, map[string]bool{
		"input": true, "fingerprints": true, "concurrency": true, "timeout": true,
		"dns-timeout": true, "dns-server": true, "pages": true, "verbose": false,
		"allow-private-network": false,
	})
	if err != nil || flags.Parse(normalized) != nil {
		if err != nil {
			fmt.Fprintf(stderr, "technograph: %v\n", err)
		}
		return 2
	}
	if config.input == "-" {
		fmt.Fprintln(stderr, "technograph: explore reserves stdin for commands; use a domain file path")
		return 2
	}
	if config.input == "" && flags.NArg() == 0 {
		fmt.Fprintln(stderr, "technograph: explore requires positional domains or --input file")
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
	inputs, err := collectInputs(flags.Args(), config.input, strings.NewReader(""))
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
	report, err := (agentapi.Runner{Service: service, MaxDomains: agentapi.DefaultMaxDomains}).Scan(ctx, "", inputs)
	if err != nil {
		fmt.Fprintf(stderr, "technograph: %v\n", err)
		return 1
	}
	if err := runExplorer(report, stdin, stdout); err != nil {
		fmt.Fprintf(stderr, "technograph: explore: %v\n", err)
		return 1
	}
	return 0
}

func runExplorer(report agentapi.Report, input io.Reader, output io.Writer) error {
	fmt.Fprintf(output, "Technograph explorer — %d domains, %d detections\n", report.Summary.Requested, report.Summary.Detections)
	fmt.Fprintln(output, "Type help for commands; type quit to exit.")
	filter := ""
	renderExplorerList(output, report.Results, filter)

	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 1024), explorerInputLimit)
	for {
		fmt.Fprint(output, "technograph> ")
		if !scanner.Scan() {
			fmt.Fprintln(output)
			return scanner.Err()
		}
		line := strings.TrimSpace(scanner.Text())
		command, argument, _ := strings.Cut(line, " ")
		command = strings.ToLower(command)
		argument = strings.TrimSpace(argument)
		switch command {
		case "", "list", "ls":
			renderExplorerList(output, report.Results, filter)
		case "filter", "find":
			if argument == "" {
				fmt.Fprintln(output, "usage: filter TEXT")
				continue
			}
			filter = strings.ToLower(argument)
			renderExplorerList(output, report.Results, filter)
		case "clear":
			filter = ""
			renderExplorerList(output, report.Results, filter)
		case "show":
			result, ok := explorerResult(report.Results, argument)
			if !ok {
				fmt.Fprintln(output, "domain not found; use show NUMBER or show DOMAIN")
				continue
			}
			view := report
			view.Results = []agentapi.DomainResult{result}
			view.Summary = summarizeForCLI(view.Results)
			fmt.Fprintln(output)
			_, _ = output.Write(renderExplanation(view))
		case "help", "?":
			renderExplorerHelp(output)
		case "quit", "exit", "q":
			fmt.Fprintln(output, "Goodbye.")
			return nil
		default:
			fmt.Fprintf(output, "unknown command %q; type help\n", safeText(command))
		}
	}
}

func renderExplorerList(output io.Writer, results []agentapi.DomainResult, filter string) {
	if filter != "" {
		fmt.Fprintf(output, "\nFilter: %s\n", safeText(filter))
	} else {
		fmt.Fprintln(output)
	}
	found := 0
	for index, result := range results {
		if !explorerMatches(result, filter) {
			continue
		}
		found++
		name := result.Domain
		if name == "" {
			name = result.Input
		}
		technologies := "none detected"
		if len(result.Technologies) > 0 {
			technologies = strings.Join(result.Technologies, ", ")
		}
		fmt.Fprintf(output, "  %2d  %-9s  %-30s  %s\n", index+1, strings.ToUpper(string(result.Status)),
			truncateText(safeText(name), 30), truncateText(safeText(technologies), 72))
	}
	if found == 0 {
		fmt.Fprintln(output, "  No matching domains.")
	}
}

func explorerMatches(result agentapi.DomainResult, filter string) bool {
	if filter == "" {
		return true
	}
	values := []string{result.Input, result.Domain, string(result.Status)}
	values = append(values, result.Technologies...)
	values = append(values, uniqueCategories(result)...)
	return strings.Contains(strings.ToLower(strings.Join(values, "\n")), filter)
}

func explorerResult(results []agentapi.DomainResult, selector string) (agentapi.DomainResult, bool) {
	if number, err := strconv.Atoi(selector); err == nil && number >= 1 && number <= len(results) {
		return results[number-1], true
	}
	for _, result := range results {
		if strings.EqualFold(selector, result.Domain) || strings.EqualFold(selector, result.Input) {
			return result, true
		}
	}
	return agentapi.DomainResult{}, false
}

func renderExplorerHelp(output io.Writer) {
	fmt.Fprintln(output, `Commands:
  list                 List domains matching the active filter
  filter TEXT          Filter by domain, status, technology, or category
  clear                Clear the active filter
  show NUMBER|DOMAIN   Show one domain's complete evidence report
  help                 Show this help
  quit                 Exit`)
}
