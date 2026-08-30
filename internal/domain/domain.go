package domain

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/b1rd33/technograph/internal/model"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

const maxDomainLineBytes = 4096

// Parse validates one bare domain and derives its registrable apex.
func Parse(raw string) (model.Domain, error) {
	// Domain suffix policy: autonomous scans are intended for public domains only
	// (see README Architecture / docs/agent-interface). Names such as
	// service.internal currently validate via PublicSuffix (unknown TLD → apex
	// derived) and rely on SafeDialer to block private HTTP. DNS queries for
	// those names are still sent to the resolver, so .internal scans leak DNS.
	// Open decision: choose
	//   A) strict public mode — reject reserved/non-public suffixes, or
	//   B) preserve internal-domain support and document the DNS exposure.
	// Until decided, behavior is unchanged.
	value := strings.TrimSpace(raw)
	if value == "" {
		return model.Domain{}, errors.New("domain is empty")
	}
	if strings.Contains(value, "://") {
		return model.Domain{}, errors.New("schemes are not allowed")
	}
	if strings.ContainsAny(value, "/?#@") {
		return model.Domain{}, errors.New("paths, queries, fragments and user info are not allowed")
	}
	if strings.Contains(value, ":") {
		return model.Domain{}, errors.New("ports and IP literals are not allowed")
	}
	value = strings.TrimSuffix(value, ".")
	if value == "" {
		return model.Domain{}, errors.New("domain is empty")
	}

	hostname, err := idna.Lookup.ToASCII(value)
	if err != nil {
		return model.Domain{}, fmt.Errorf("invalid internationalized domain: %w", err)
	}
	hostname = strings.ToLower(hostname)
	if net.ParseIP(hostname) != nil {
		return model.Domain{}, errors.New("IP literals are not allowed")
	}
	if err := validateASCIIHostname(hostname); err != nil {
		return model.Domain{}, err
	}
	apex, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err != nil {
		return model.Domain{}, fmt.Errorf("cannot derive registrable apex: %w", err)
	}
	return model.Domain{Hostname: hostname, Apex: strings.ToLower(apex)}, nil
}

func validateASCIIHostname(hostname string) error {
	if len(hostname) > 253 {
		return errors.New("domain exceeds 253 bytes")
	}
	labels := strings.Split(hostname, ".")
	if len(labels) < 2 {
		return errors.New("domain must contain a public suffix")
	}
	for _, label := range labels {
		if len(label) == 0 {
			return errors.New("domain contains an empty label")
		}
		if len(label) > 63 {
			return fmt.Errorf("domain label %q exceeds 63 bytes", label)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("domain label %q starts or ends with a hyphen", label)
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') ||
				(character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return fmt.Errorf("domain label %q contains an invalid character", label)
		}
	}
	return nil
}

// Read validates and deduplicates one-domain-per-line input.
func Read(r io.Reader, source string) ([]model.Domain, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024), maxDomainLineBytes)
	domains := make([]model.Domain, 0)
	seen := make(map[string]struct{})
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if lineNumber == 1 {
			line = strings.TrimPrefix(line, "\ufeff")
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		parsed, err := Parse(trimmed)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", source, lineNumber, err)
		}
		if _, duplicate := seen[parsed.Hostname]; duplicate {
			continue
		}
		seen[parsed.Hostname] = struct{}{}
		domains = append(domains, parsed)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", source, err)
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("%s: no domains found", source)
	}
	return domains, nil
}

// Load opens and parses a domain file.
func Load(path string) ([]model.Domain, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open domain file %s: %w", path, err)
	}
	defer file.Close()
	return Read(file, path)
}
