package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	technograph "github.com/b1rd33/technograph"
	"github.com/b1rd33/technograph/internal/fingerprint"
)

func escapeMD(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\r\n", "<br>")
	value = strings.ReplaceAll(value, "\n", "<br>")
	value = strings.ReplaceAll(value, "\r", "<br>")
	return value
}

func findRepoRoot() string {
	candidates := []string{}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, wd)
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Dir(exe))
	}
	for _, start := range candidates {
		dir := start
		for i := 0; i < 10; i++ {
			if _, err := os.Stat(filepath.Join(dir, "fingerprints.json")); err == nil {
				return dir
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

func main() {
	data := technograph.DefaultFingerprints()
	database, warnings, err := fingerprint.Load(data, true)
	if err != nil {
		log.Fatalf("load bundled fingerprints: %v", err)
	}
	if len(warnings) != 0 {
		log.Fatalf("unexpected warnings for bundled DB: %v", warnings)
	}
	descriptors := database.Descriptors()

	repoRoot := findRepoRoot()
	outPath := filepath.Join(repoRoot, "docs", "fingerprints.md")

	techSet := make(map[string]struct{})
	for _, d := range descriptors {
		techSet[d.Technology] = struct{}{}
	}

	var buf bytes.Buffer
	buf.WriteString("<!-- Generated from fingerprints.json — do not edit by hand. Run `make fingerprints-doc` to regenerate. -->\n")
	buf.WriteString("# Fingerprints\n\n")
	buf.WriteString(fmt.Sprintf("Source: `fingerprints.json` (`schema_version: 1`) — %d technologies, %d patterns.\n\n", len(techSet), database.Count()))
	buf.WriteString("This document is generated from the bundled normalized fingerprint database via `fingerprint.Load(strict=true) → Descriptors()`. It is the single source of truth for offline inspection. See `technograph fingerprints --help` for live inspection.\n\n")
	buf.WriteString("| Technology | Channel | Target | Selector | Origins | Pattern | Confidence | Categories |\n")
	buf.WriteString("|---|---|---|---|---|---|---|---|\n")
	for _, d := range descriptors {
		origins := strings.Join(d.Origins, ", ")
		categories := strings.Join(d.Categories, ", ")
		buf.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | `%s` | %d | %s |\n",
			escapeMD(d.Technology),
			escapeMD(string(d.Channel)),
			escapeMD(string(d.Target)),
			escapeMD(d.Selector),
			escapeMD(origins),
			escapeMD(d.Pattern),
			d.Confidence,
			escapeMD(categories),
		))
	}
	buf.WriteString("\n## Channels\n\n")
	buf.WriteString("Normalized channels are `header`, `script`, `cookie`, `html`, `meta`, `js`, `dns_txt`, `dns_cname`, `dns_mx` (see `schemas/fingerprint-database.schema.json` and `internal/model/signals.go`). The bundled database uses a subset: `header`, `script`, `cookie`, `html`, `dns_txt`, `dns_cname`, `dns_mx`.\n\n")
	buf.WriteString("Origins scope `script` patterns to their HTML source type: `html:script-src` and `html:script-src-absolute` for external `scriptSrc`, `html:inline-script` for inline `script` content. Other channels have no origins. Categories (e.g. Payments, Analytics) are descriptive metadata and do not affect detection.\n\n")
	buf.WriteString("## Inspecting and validating\n\n")
	buf.WriteString("```console\n")
	buf.WriteString("technograph fingerprints\n")
	buf.WriteString("technograph fingerprints --technology hubspot --format table\n")
	buf.WriteString("technograph fingerprints --channel script --channel header\n")
	buf.WriteString("technograph fingerprints --fingerprints custom.json\n")
	buf.WriteString("technograph fingerprints --fingerprints custom.json --validate\n")
	buf.WriteString("```\n\n")
	buf.WriteString("- `technograph fingerprints` lists the bundled catalog (permissive external loading reports skipped-pattern warnings to stderr).\n")
	buf.WriteString("- `--technology` is repeatable, case-insensitive exact match; `--channel` accepts only the nine normalized channels (union).\n")
	buf.WriteString("- `--validate` requires `--fingerprints <file>` and strictly validates via `fingerprint.Load(data, true)` with no output on success. It proves the file can be loaded and compiled, not that a technology will match a live site.\n")
	buf.WriteString("- Filtering and table display make no network requests. The original `output.json` assignment artifact is unchanged.\n")

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		log.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(outPath, buf.Bytes(), 0o644); err != nil {
		log.Fatalf("write %s: %v", outPath, err)
	}
}
