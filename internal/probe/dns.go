package probe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/b1rd33/technograph/internal/model"
	"github.com/miekg/dns"
)

type dnsExchanger interface {
	ExchangeContext(context.Context, *dns.Msg, string) (*dns.Msg, time.Duration, error)
}

// DNSOptions configures exact DNS RR queries.
type DNSOptions struct {
	Servers []string
	Timeout time.Duration
	UDP     dnsExchanger
	TCP     dnsExchanger
	Logger  *slog.Logger
}

// DNSProbe queries exact MX, TXT, and apex CNAME RRsets.
type DNSProbe struct {
	servers []string
	timeout time.Duration
	udp     dnsExchanger
	tcp     dnsExchanger
	logger  *slog.Logger
}

// NormalizeDNSServers validates opt-in resolver addresses and supplies the
// standard DNS port when omitted. Resolver hostnames are intentionally not
// accepted because resolving a resolver would depend on another resolver.
func NormalizeDNSServers(values []string) ([]string, error) {
	servers := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, errors.New("DNS resolver cannot be empty")
		}
		var host, port string
		if ip := net.ParseIP(value); ip != nil {
			host, port = ip.String(), "53"
		} else {
			var err error
			host, port, err = net.SplitHostPort(value)
			if err != nil {
				return nil, fmt.Errorf("invalid DNS resolver %q: use an IP address with an optional port", value)
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return nil, fmt.Errorf("invalid DNS resolver %q: host must be an IP address", value)
			}
			host = ip.String()
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return nil, fmt.Errorf("invalid DNS resolver %q: port must be between 1 and 65535", value)
		}
		normalized := net.JoinHostPort(host, strconv.Itoa(portNumber))
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		servers = append(servers, normalized)
	}
	if len(servers) == 0 {
		return nil, errors.New("DNS resolver has no nameservers")
	}
	return servers, nil
}

// NewSystemDNSProbe reads resolver settings from resolv.conf. This is supported
// on the macOS and Unix-like environments targeted by the assignment.
func NewSystemDNSProbe(timeout time.Duration, logger *slog.Logger) (*DNSProbe, error) {
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("read system DNS configuration: %w", err)
	}
	servers := make([]string, 0, len(config.Servers))
	for _, server := range config.Servers {
		servers = append(servers, net.JoinHostPort(server, config.Port))
	}
	return NewDNSProbe(DNSOptions{Servers: servers, Timeout: timeout, Logger: logger})
}

func NewDNSProbe(options DNSOptions) (*DNSProbe, error) {
	if len(options.Servers) == 0 {
		return nil, errors.New("DNS resolver has no nameservers")
	}
	if options.Timeout <= 0 {
		options.Timeout = 3 * time.Second
	}
	if options.UDP == nil {
		options.UDP = &dns.Client{Net: "udp", Timeout: options.Timeout}
	}
	if options.TCP == nil {
		options.TCP = &dns.Client{Net: "tcp", Timeout: options.Timeout}
	}
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	return &DNSProbe{
		servers: append([]string(nil), options.Servers...), timeout: options.Timeout,
		udp: options.UDP, tcp: options.TCP, logger: options.Logger,
	}, nil
}

type dnsQueryResult struct {
	recordType string
	records    []string
	status     string
	err        error
}

// Probe queries all required record types concurrently. One failed type never
// hides successful records from another type.
func (probe *DNSProbe) Probe(ctx context.Context, apex string) (model.DNSResult, []model.Signal) {
	result := model.DNSResult{
		Apex: strings.ToLower(strings.TrimSuffix(apex, ".")),
		MX:   []string{}, TXT: []string{}, CNAME: []string{},
		Status: make(map[string]string), Errors: make(map[string]string),
	}
	types := []struct {
		name  string
		qtype uint16
	}{{"mx", dns.TypeMX}, {"txt", dns.TypeTXT}, {"cname", dns.TypeCNAME}}
	completed := make(chan dnsQueryResult, len(types))
	for _, recordType := range types {
		recordType := recordType
		go func() {
			records, status, err := probe.query(ctx, result.Apex, recordType.qtype)
			completed <- dnsQueryResult{recordType.name, records, status, err}
		}()
	}
	for range types {
		outcome := <-completed
		result.Status[outcome.recordType] = outcome.status
		if outcome.err != nil {
			result.Errors[outcome.recordType] = outcome.err.Error()
			probe.logger.Debug("DNS query failed", "apex", result.Apex, "type", outcome.recordType, "error", outcome.err)
		}
		switch outcome.recordType {
		case "mx":
			result.MX = outcome.records
		case "txt":
			result.TXT = outcome.records
		case "cname":
			result.CNAME = outcome.records
		}
	}

	signals := make([]model.Signal, 0, len(result.MX)+len(result.TXT)+len(result.CNAME))
	for _, record := range result.MX {
		signals = append(signals, model.Signal{Channel: model.ChannelDNSMX, Value: record, Origin: "dns:" + result.Apex + ":mx"})
	}
	for _, record := range result.TXT {
		signals = append(signals, model.Signal{Channel: model.ChannelDNSTXT, Value: record, Origin: "dns:" + result.Apex + ":txt"})
	}
	for _, record := range result.CNAME {
		signals = append(signals, model.Signal{Channel: model.ChannelDNSCNAME, Value: record, Origin: "dns:" + result.Apex + ":cname"})
	}
	return result, signals
}

func (probe *DNSProbe) query(ctx context.Context, apex string, qtype uint16) ([]string, string, error) {
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(apex), qtype)
	message.RecursionDesired = true
	var lastError error
	for _, server := range probe.servers {
		queryContext, cancel := context.WithTimeout(ctx, probe.timeout)
		response, _, err := probe.udp.ExchangeContext(queryContext, message.Copy(), server)
		// miekg/dns can return a partially decoded message together with an
		// unpacking error. Retry those responses over TCP as well as responses
		// carrying the DNS truncation bit; both indicate that useful UDP bytes
		// arrived but could not be consumed reliably.
		if response != nil && (response.Truncated || err != nil) {
			response, _, err = probe.tcp.ExchangeContext(queryContext, message.Copy(), server)
		}
		cancel()
		if err != nil {
			lastError = err
			if ctx.Err() != nil {
				return nil, "cancelled", ctx.Err()
			}
			continue
		}
		if response == nil {
			lastError = errors.New("empty DNS response")
			continue
		}
		switch response.Rcode {
		case dns.RcodeNameError:
			return []string{}, "nxdomain", nil
		case dns.RcodeSuccess:
			records := normalizeAnswers(response.Answer, qtype)
			if len(records) == 0 {
				return []string{}, "nodata", nil
			}
			return records, "ok", nil
		default:
			lastError = fmt.Errorf("DNS rcode %s", dns.RcodeToString[response.Rcode])
		}
	}
	if lastError == nil {
		lastError = errors.New("DNS query failed")
	}
	return []string{}, "error", lastError
}

func normalizeAnswers(answers []dns.RR, qtype uint16) []string {
	records := make([]string, 0)
	for _, answer := range answers {
		switch record := answer.(type) {
		case *dns.MX:
			if qtype == dns.TypeMX {
				records = append(records, strings.ToLower(strings.TrimSuffix(record.Mx, ".")))
			}
		case *dns.TXT:
			if qtype == dns.TypeTXT {
				records = append(records, strings.Join(record.Txt, ""))
			}
		case *dns.CNAME:
			if qtype == dns.TypeCNAME {
				records = append(records, strings.ToLower(strings.TrimSuffix(record.Target, ".")))
			}
		}
	}
	sort.Strings(records)
	return compact(records)
}

func compact(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	output := values[:0]
	for _, value := range values {
		if value == "" || (len(output) > 0 && output[len(output)-1] == value) {
			continue
		}
		output = append(output, value)
	}
	return output
}
