package cli

import (
	"io"

	"github.com/b1rd33/technograph/internal/domain"
	"github.com/b1rd33/technograph/internal/model"
)

// ParseDomain validates one bare domain and derives its registrable apex.
// Schemes, paths, ports and IP literals are deliberately rejected because the
// CLI contract is one company domain per line, not arbitrary URLs.
func ParseDomain(raw string) (model.Domain, error) {
	return domain.Parse(raw)
}

// ReadDomains reads, validates and deduplicates domains from r. Blank lines and
// lines whose first non-space character is '#' are ignored.
func ReadDomains(r io.Reader, source string) ([]model.Domain, error) {
	return domain.Read(r, source)
}

// LoadDomains opens and parses a domain file.
func LoadDomains(path string) ([]model.Domain, error) {
	return domain.Load(path)
}
