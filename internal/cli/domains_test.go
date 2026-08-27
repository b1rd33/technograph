package cli

import (
	"errors"
	"strings"
	"testing"
)

func TestParseDomain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		input        string
		wantHostname string
		wantApex     string
	}{
		{name: "apex", input: "Example.COM", wantHostname: "example.com", wantApex: "example.com"},
		{name: "trailing dot", input: "example.com.", wantHostname: "example.com", wantApex: "example.com"},
		{name: "subdomain", input: "www.example.com", wantHostname: "www.example.com", wantApex: "example.com"},
		{name: "multi label suffix", input: "www.example.co.uk", wantHostname: "www.example.co.uk", wantApex: "example.co.uk"},
		{name: "unicode", input: "bücher.de", wantHostname: "xn--bcher-kva.de", wantApex: "xn--bcher-kva.de"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseDomain(test.input)
			if err != nil {
				t.Fatalf("ParseDomain(%q): %v", test.input, err)
			}
			if got.Hostname != test.wantHostname || got.Apex != test.wantApex {
				t.Fatalf("ParseDomain(%q) = %#v, want hostname=%q apex=%q", test.input, got, test.wantHostname, test.wantApex)
			}
		})
	}
}

func TestParseDomainRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	tests := []string{
		"",
		"localhost",
		"https://example.com",
		"example.com/path",
		"example.com?query=1",
		"example.com#fragment",
		"user@example.com",
		"example.com:443",
		"127.0.0.1",
		"[::1]",
		"bad_domain.com",
		"-bad.com",
		"bad-.com",
		"bad..com",
		"*.example.com",
	}

	for _, input := range tests {
		input := input
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			if got, err := ParseDomain(input); err == nil {
				t.Fatalf("ParseDomain(%q) = %#v, want error", input, got)
			}
		})
	}
}

func TestReadDomainsDeduplicatesInInputOrder(t *testing.T) {
	t.Parallel()

	input := "\ufeff# assignment domains\n\nBÜCHER.de\nexample.com\nbücher.de\nwww.example.co.uk\n"
	domains, err := ReadDomains(strings.NewReader(input), "domains.txt")
	if err != nil {
		t.Fatalf("ReadDomains: %v", err)
	}
	if got, want := len(domains), 3; got != want {
		t.Fatalf("domain count = %d, want %d: %#v", got, want, domains)
	}
	if domains[0].Hostname != "xn--bcher-kva.de" ||
		domains[1].Hostname != "example.com" ||
		domains[2].Hostname != "www.example.co.uk" {
		t.Fatalf("unexpected order: %#v", domains)
	}
}

func TestReadDomainsReportsSourceLine(t *testing.T) {
	t.Parallel()

	_, err := ReadDomains(strings.NewReader("example.com\nbad_domain.com\n"), "input.txt")
	if err == nil || !strings.Contains(err.Error(), "input.txt:2:") {
		t.Fatalf("error = %v, want source and line", err)
	}
}

func TestReadDomainsRejectsEmptyFile(t *testing.T) {
	t.Parallel()

	_, err := ReadDomains(strings.NewReader("\n # comments only\n"), "empty.txt")
	if err == nil || !strings.Contains(err.Error(), "no domains found") {
		t.Fatalf("error = %v, want no-domains error", err)
	}
}

type failingReader struct {
	err error
}

func (reader failingReader) Read([]byte) (int, error) {
	return 0, reader.err
}

func TestReadDomainsPropagatesReaderError(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("disk failed")
	_, err := ReadDomains(failingReader{err: sentinel}, "broken.txt")
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want wrapped %v", err, sentinel)
	}
}

func TestLoadAssignmentDomains(t *testing.T) {
	t.Parallel()

	domains, err := LoadDomains("../../domains.txt")
	if err != nil {
		t.Fatalf("LoadDomains: %v", err)
	}
	if got, want := len(domains), 20; got != want {
		t.Fatalf("domain count = %d, want %d", got, want)
	}
	for _, domain := range domains {
		if domain.Hostname != domain.Apex {
			t.Errorf("assignment domain is not an apex: %#v", domain)
		}
	}
}

func FuzzParseDomain(f *testing.F) {
	for _, seed := range []string{
		"example.com",
		"www.example.co.uk",
		"bücher.de",
		"bad_domain.com",
		"https://example.com",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		domain, err := ParseDomain(input)
		if err != nil {
			return
		}
		if domain.Hostname == "" || domain.Apex == "" {
			t.Fatalf("successful parse returned empty fields: %#v", domain)
		}
		if domain.Hostname != strings.ToLower(domain.Hostname) {
			t.Fatalf("hostname is not lowercase: %q", domain.Hostname)
		}
		if strings.HasSuffix(domain.Hostname, ".") {
			t.Fatalf("hostname has trailing dot: %q", domain.Hostname)
		}
	})
}
