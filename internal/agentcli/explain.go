package agentcli

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/b1rd33/technograph/internal/agentapi"
	"github.com/b1rd33/technograph/internal/model"
)

func runExplain(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, bundled []byte) int {
	flags := flag.NewFlagSet("technograph explain", flag.ContinueOnError)
	flags.SetOutput(stderr)
	config := scanFlags{}
	flags.StringVar(&config.input, "input", "", "domain file path, or - for stdin")
	flags.StringVar(&config.output, "output", "", "output path (default stdout)")
	flags.StringVar(&config.fingerprints, "fingerprints", "", "external normalized fingerprint JSON")
	flags.IntVar(&config.concurrency, "concurrency", 10, "maximum domains scanned concurrently")
	flags.DurationVar(&config.httpTimeout, "timeout", 8*time.Second, "HTTP timeout per domain")
	flags.DurationVar(&config.dnsTimeout, "dns-timeout", 3*time.Second, "timeout per DNS record query")
	flags.IntVar(&config.pageLimit, "pages", 1, "maximum same-host HTML pages per domain (1-5)")
	flags.Var(&config.dnsServers, "dns-server", "custom DNS resolver IP[:port] (repeatable)")
	flags.BoolVar(&config.verbose, "verbose", false, "enable verbose diagnostics on stderr")
	flags.BoolVar(&config.allowPrivateNet, "allow-private-network", false, "disable autonomous SSRF protection for this local invocation")
	if wantsHelp(args) {
		subcommandUsage(stdout, "technograph explain [flags] [domain ...]", flags,
			`Runs the same deterministic scanner as "scan" and formats its evidence for
people. The report includes technology matches, HTTP/DNS coverage, timing, and
partial, blocked, failed, or invalid conditions. When no domains are provided,
input is read from stdin.

Examples:
  technograph explain stripe.com
  technograph explain stripe.com shopify.com
  technograph explain stripe.com --pages 3
  technograph explain --input domains.txt
  technograph explain --input domains.txt --output evidence-report.txt`)
		return 0
	}
	normalized, err := intersperse(args, map[string]bool{
		"input": true, "output": true, "fingerprints": true,
		"concurrency": true, "timeout": true, "dns-timeout": true, "dns-server": true, "pages": true,
		"verbose": false, "allow-private-network": false,
	})
	if err != nil || flags.Parse(normalized) != nil {
		if err != nil {
			fmt.Fprintf(stderr, "technograph: %v\n", err)
		}
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
	report, err := (agentapi.Runner{Service: service, MaxDomains: agentapi.DefaultMaxDomains}).Scan(ctx, "", inputs)
	if err != nil {
		fmt.Fprintf(stderr, "technograph: %v\n", err)
		return 1
	}
	return writeBytes(renderExplanation(report), config.output, stdout, stderr)
}

func renderExplanation(report agentapi.Report) []byte {
	var buffer bytes.Buffer
	fmt.Fprintln(&buffer, "Technograph evidence report")
	fmt.Fprintf(&buffer, "Generated: %s\n", report.GeneratedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&buffer, "Summary: %d requested, %d detections, %d ok, %d partial, %d blocked, %d failed, %d invalid\n",
		report.Summary.Requested, report.Summary.Detections, report.Summary.OK, report.Summary.Partial,
		report.Summary.Blocked, report.Summary.Failed, report.Summary.Invalid)

	for _, result := range report.Results {
		fmt.Fprintln(&buffer)
		name := result.Domain
		if name == "" {
			name = result.Input
		}
		fmt.Fprintf(&buffer, "%s  [%s]\n", safeText(name), strings.ToUpper(string(result.Status)))
		if result.ElapsedMS > 0 {
			fmt.Fprintf(&buffer, "  Elapsed: %s\n", time.Duration(result.ElapsedMS)*time.Millisecond)
		}
		renderTechnologies(&buffer, result)
		renderCoverage(&buffer, result)
		renderIssues(&buffer, result)
	}
	return buffer.Bytes()
}

func renderTechnologies(buffer *bytes.Buffer, result agentapi.DomainResult) {
	if len(result.Technologies) == 0 {
		fmt.Fprintln(buffer, "  Technologies: none detected")
		return
	}
	fmt.Fprintf(buffer, "  Technologies (%d):\n", len(result.Technologies))
	technologies := append([]string(nil), result.Technologies...)
	sort.Strings(technologies)
	evidence := append([]model.Evidence(nil), result.Evidence...)
	sort.SliceStable(evidence, func(left, right int) bool {
		if evidence[left].Technology != evidence[right].Technology {
			return evidence[left].Technology < evidence[right].Technology
		}
		if evidence[left].Channel != evidence[right].Channel {
			return evidence[left].Channel < evidence[right].Channel
		}
		if evidence[left].Selector != evidence[right].Selector {
			return evidence[left].Selector < evidence[right].Selector
		}
		if evidence[left].Origin != evidence[right].Origin {
			return evidence[left].Origin < evidence[right].Origin
		}
		return evidence[left].Matched < evidence[right].Matched
	})
	for _, technology := range technologies {
		label := safeText(technology)
		if categories := result.TechnologyCategories[technology]; len(categories) > 0 {
			label += " [" + safeText(strings.Join(categories, ", ")) + "]"
		}
		fmt.Fprintf(buffer, "    %s\n", label)
		for _, item := range evidence {
			if item.Technology != technology {
				continue
			}
			selector := ""
			if item.Selector != "" {
				selector = " " + strconv.Quote(safeText(item.Selector))
			}
			fmt.Fprintf(buffer, "      - %s%s matched %s\n", channelLabel(item.Channel), selector, strconv.Quote(safeText(item.Matched)))
			source := safeText(item.Origin)
			if item.PageURL != "" {
				source += " at " + safeText(item.PageURL)
			}
			fmt.Fprintf(buffer, "        Source: %s; confidence: %d\n", source, item.Confidence)
		}
	}
}

func renderCoverage(buffer *bytes.Buffer, result agentapi.DomainResult) {
	if result.HTTP != nil {
		if result.HTTP.Error != "" {
			fmt.Fprintln(buffer, "  HTTP: unavailable")
		} else {
			fmt.Fprintf(buffer, "  HTTP: %d", result.HTTP.StatusCode)
			if result.HTTP.FinalURL != "" {
				fmt.Fprintf(buffer, " %s", safeText(result.HTTP.FinalURL))
			}
			if result.HTTP.Redirects > 0 {
				fmt.Fprintf(buffer, " (%d %s)", result.HTTP.Redirects, plural(result.HTTP.Redirects, "redirect", "redirects"))
			}
			if result.HTTP.Blocked || result.HTTP.Challenge {
				fmt.Fprint(buffer, " [blocked]")
			}
			fmt.Fprintln(buffer)
		}
		if result.HTTP.PageCount > 1 {
			fmt.Fprintf(buffer, "  Pages: %d total (%d secondary)\n", result.HTTP.PageCount, len(result.HTTP.Pages))
			for _, page := range result.HTTP.Pages {
				status := strconv.Itoa(page.StatusCode)
				if page.Error != "" {
					status = "error"
				} else if page.Blocked {
					status += ", blocked"
				}
				address := page.FinalURL
				if address == "" {
					address = page.RequestedURL
				}
				fmt.Fprintf(buffer, "    - %s [%s]\n", safeText(address), status)
			}
		}
	}
	if result.DNS != nil && len(result.DNS.Status) > 0 {
		fmt.Fprintf(buffer, "  DNS: MX %s, TXT %s, CNAME %s\n",
			dnsStatus(result.DNS.Status, "mx"), dnsStatus(result.DNS.Status, "txt"), dnsStatus(result.DNS.Status, "cname"))
	}
}

func renderIssues(buffer *bytes.Buffer, result agentapi.DomainResult) {
	if len(result.Warnings) == 0 && len(result.Errors) == 0 {
		return
	}
	fmt.Fprintln(buffer, "  Issues:")
	for _, issue := range result.Warnings {
		renderIssue(buffer, "warning", issue)
	}
	for _, issue := range result.Errors {
		renderIssue(buffer, "error", issue)
	}
}

func renderIssue(buffer *bytes.Buffer, level string, issue agentapi.Issue) {
	channel := ""
	if issue.Channel != "" {
		channel = "/" + safeText(issue.Channel)
	}
	fmt.Fprintf(buffer, "    - %s %s%s: %s\n", level, safeText(issue.Code), channel, safeText(issue.Message))
}

func channelLabel(channel model.Channel) string {
	switch channel {
	case model.ChannelHeader:
		return "HTTP header"
	case model.ChannelScript:
		return "script"
	case model.ChannelCookie:
		return "cookie"
	case model.ChannelHTML:
		return "HTML"
	case model.ChannelMeta:
		return "meta tag"
	case model.ChannelJS:
		return "JavaScript global"
	case model.ChannelDNSTXT:
		return "DNS TXT"
	case model.ChannelDNSCNAME:
		return "DNS CNAME"
	case model.ChannelDNSMX:
		return "DNS MX"
	default:
		return safeText(string(channel))
	}
}

func dnsStatus(statuses map[string]string, key string) string {
	if value := statuses[key]; value != "" {
		return safeText(value)
	}
	return "unknown"
}

func plural(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}

func safeText(value string) string {
	return strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return unicode.ReplacementChar
		}
		return character
	}, value)
}
