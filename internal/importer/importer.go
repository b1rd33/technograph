// Package importer converts native Wappalyzer technology files into
// Technograph's explicit normalized fingerprint representation.
package importer

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/b1rd33/technograph/internal/fingerprint"
)

const (
	SchemaVersion      = "1.0"
	maximumFileBytes   = 64 << 20
	maximumSourceBytes = 256 << 20
)

type Options struct {
	Input          string
	CategoriesPath string
	Technologies   []string
}

type Pattern struct {
	Channel  string   `json:"channel"`
	Regex    string   `json:"regex"`
	Target   string   `json:"target,omitempty"`
	Selector string   `json:"selector,omitempty"`
	Origins  []string `json:"origins,omitempty"`
}

type Technology struct {
	Categories []string  `json:"categories,omitempty"`
	Patterns   []Pattern `json:"patterns"`
}

type Database struct {
	SchemaVersion int                   `json:"schema_version"`
	Technologies  map[string]Technology `json:"technologies"`
}

type Summary struct {
	SourceFiles          int `json:"source_files"`
	TechnologiesSeen     int `json:"technologies_seen"`
	TechnologiesImported int `json:"technologies_imported"`
	PatternsSeen         int `json:"patterns_seen"`
	PatternsImported     int `json:"patterns_imported"`
	PatternsSkipped      int `json:"patterns_skipped"`
	DuplicatesRemoved    int `json:"duplicates_removed"`
	UnsupportedRegexes   int `json:"unsupported_regexes"`
	UnresolvedCategories int `json:"unresolved_categories"`
}

type Issue struct {
	Kind       string `json:"kind"`
	Technology string `json:"technology,omitempty"`
	Field      string `json:"field,omitempty"`
	Selector   string `json:"selector,omitempty"`
	Pattern    string `json:"pattern,omitempty"`
	Message    string `json:"message"`
}

type Report struct {
	SchemaVersion string         `json:"schema_version"`
	SourceFiles   []string       `json:"source_files"`
	Summary       Summary        `json:"summary"`
	Channels      map[string]int `json:"channels"`
	Issues        []Issue        `json:"issues"`
}

type importState struct {
	database   Database
	report     Report
	seen       map[string]map[string]struct{}
	categories map[string]string
	selected   map[string]struct{}
	found      map[string]struct{}
}

// Import reads one native technology JSON file or a directory of JSON files.
// It is offline, deterministic, and validates every emitted regex with Go RE2.
func Import(options Options) (Database, Report, error) {
	if strings.TrimSpace(options.Input) == "" {
		return Database{}, Report{}, errors.New("input path is required")
	}
	categoryNames, err := readCategories(options.CategoriesPath)
	if err != nil {
		return Database{}, Report{}, err
	}
	files, err := sourceFiles(options.Input, options.CategoriesPath)
	if err != nil {
		return Database{}, Report{}, err
	}
	state := importState{
		database: Database{SchemaVersion: 1, Technologies: make(map[string]Technology)},
		report:   Report{SchemaVersion: SchemaVersion, Channels: make(map[string]int), Issues: []Issue{}},
		seen:     make(map[string]map[string]struct{}), categories: categoryNames,
		selected: make(map[string]struct{}), found: make(map[string]struct{}),
	}
	for _, technology := range options.Technologies {
		technology = strings.TrimSpace(technology)
		if technology == "" {
			return Database{}, Report{}, errors.New("technology filter cannot be empty")
		}
		state.selected[technology] = struct{}{}
	}
	totalBytes := int64(0)
	for _, path := range files {
		info, err := os.Stat(path)
		if err != nil {
			return Database{}, Report{}, fmt.Errorf("stat source %s: %w", path, err)
		}
		if info.Size() > maximumFileBytes {
			return Database{}, Report{}, fmt.Errorf("source %s exceeds %d bytes", path, maximumFileBytes)
		}
		totalBytes += info.Size()
		if totalBytes > maximumSourceBytes {
			return Database{}, Report{}, fmt.Errorf("source corpus exceeds %d bytes", maximumSourceBytes)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return Database{}, Report{}, fmt.Errorf("read source %s: %w", path, err)
		}
		if err := state.importFile(path, data); err != nil {
			return Database{}, Report{}, err
		}
		state.report.SourceFiles = append(state.report.SourceFiles, filepath.Base(path))
	}
	for technology := range state.selected {
		if _, ok := state.found[technology]; !ok {
			return Database{}, Report{}, fmt.Errorf("selected technology %q was not found", technology)
		}
	}
	state.finalize()
	encoded, err := json.Marshal(state.database)
	if err != nil {
		return Database{}, Report{}, fmt.Errorf("encode normalized database: %w", err)
	}
	_, warnings, err := fingerprint.Load(encoded, true)
	if err != nil {
		return Database{}, Report{}, fmt.Errorf("validate normalized database: %w", err)
	}
	if len(warnings) != 0 {
		return Database{}, Report{}, fmt.Errorf("validate normalized database: unexpected warnings: %v", warnings)
	}
	return state.database, state.report, nil
}

func (state *importState) importFile(path string, data []byte) error {
	var technologies map[string]json.RawMessage
	if err := json.Unmarshal(data, &technologies); err != nil {
		return fmt.Errorf("decode source %s: %w", path, err)
	}
	if _, normalized := technologies["schema_version"]; normalized {
		return fmt.Errorf("source %s looks normalized already; expected native Wappalyzer technology JSON", path)
	}
	names := make([]string, 0, len(technologies))
	for name := range technologies {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if len(state.selected) > 0 {
			if _, ok := state.selected[name]; !ok {
				continue
			}
		}
		state.found[name] = struct{}{}
		state.report.Summary.TechnologiesSeen++
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(technologies[name], &fields); err != nil {
			return fmt.Errorf("decode %s technology %q: %w", path, name, err)
		}
		if err := state.importTechnology(name, fields); err != nil {
			return fmt.Errorf("decode %s technology %q: %w", path, name, err)
		}
	}
	return nil
}

func (state *importState) importTechnology(name string, fields map[string]json.RawMessage) error {
	definition := state.database.Technologies[name]
	if categories, ok := fields["cats"]; ok {
		ids, err := categoryIDs(categories)
		if err != nil {
			return fmt.Errorf("cats: %w", err)
		}
		for _, id := range ids {
			if category, ok := state.categories[id]; ok {
				definition.Categories = append(definition.Categories, category)
			} else {
				state.report.Summary.UnresolvedCategories++
				state.report.Issues = append(state.report.Issues, Issue{Kind: "unresolved_category", Technology: name, Field: "cats", Message: "category " + id + " was not found in the category mapping"})
			}
		}
	}
	for _, mapping := range []struct {
		field, channel string
		origins        []string
	}{
		{"scriptSrc", "script", []string{"html:script-src", "html:script-src-absolute"}},
		{"scripts", "script", []string{"html:inline-script"}},
		{"html", "html", nil},
	} {
		if raw, ok := fields[mapping.field]; ok {
			patterns, err := patternList(raw)
			if err != nil {
				return fmt.Errorf("%s: %w", mapping.field, err)
			}
			for _, pattern := range patterns {
				state.addPattern(name, mapping.field, Pattern{Channel: mapping.channel, Regex: pattern, Origins: mapping.origins})
			}
		}
	}
	for _, mapping := range []struct{ field, channel string }{
		{"headers", "header"}, {"cookies", "cookie"}, {"meta", "meta"},
	} {
		if raw, ok := fields[mapping.field]; ok {
			entries, err := patternMap(raw)
			if err != nil {
				return fmt.Errorf("%s: %w", mapping.field, err)
			}
			for _, entry := range entries {
				for _, pattern := range entry.patterns {
					state.addPattern(name, mapping.field, Pattern{Channel: mapping.channel, Regex: pattern, Selector: entry.selector})
				}
			}
		}
	}
	if raw, ok := fields["dns"]; ok {
		entries, err := patternMap(raw)
		if err != nil {
			return fmt.Errorf("dns: %w", err)
		}
		for _, entry := range entries {
			channel := map[string]string{"MX": "dns_mx", "TXT": "dns_txt", "CNAME": "dns_cname"}[strings.ToUpper(entry.selector)]
			for _, pattern := range entry.patterns {
				if channel == "" {
					state.skip(name, "dns", entry.selector, pattern, "unsupported_channel", "DNS record type is not collected")
					continue
				}
				state.addPattern(name, "dns", Pattern{Channel: channel, Regex: pattern})
			}
		}
	}
	for _, field := range []string{"text", "css", "robots", "url", "xhr", "js", "dom", "certIssuer"} {
		if raw, ok := fields[field]; ok {
			for _, entry := range countablePatterns(raw) {
				state.skip(name, field, entry.selector, entry.pattern, "unsupported_channel", "signal channel is not collected with equivalent semantics")
			}
		}
	}
	latest := state.database.Technologies[name]
	latest.Categories = uniqueSorted(append(latest.Categories, definition.Categories...))
	state.database.Technologies[name] = latest
	return nil
}

func (state *importState) addPattern(technology, field string, pattern Pattern) {
	state.report.Summary.PatternsSeen++
	if err := fingerprint.ValidateRegex(pattern.Regex); err != nil {
		state.report.Summary.PatternsSkipped++
		state.report.Summary.UnsupportedRegexes++
		state.report.Issues = append(state.report.Issues, Issue{Kind: "unsupported_regex", Technology: technology, Field: field, Selector: pattern.Selector, Pattern: pattern.Regex, Message: err.Error()})
		return
	}
	key := pattern.Channel + "\x00" + pattern.Target + "\x00" + strings.ToLower(pattern.Selector) + "\x00" + strings.Join(pattern.Origins, "\x01") + "\x00" + pattern.Regex
	if state.seen[technology] == nil {
		state.seen[technology] = make(map[string]struct{})
	}
	if _, duplicate := state.seen[technology][key]; duplicate {
		state.report.Summary.PatternsSkipped++
		state.report.Summary.DuplicatesRemoved++
		state.report.Issues = append(state.report.Issues, Issue{Kind: "duplicate", Technology: technology, Field: field, Selector: pattern.Selector, Pattern: pattern.Regex, Message: "identical normalized pattern already imported"})
		return
	}
	state.seen[technology][key] = struct{}{}
	definition := state.database.Technologies[technology]
	definition.Patterns = append(definition.Patterns, pattern)
	state.database.Technologies[technology] = definition
	state.report.Summary.PatternsImported++
	state.report.Channels[pattern.Channel]++
}

func (state *importState) skip(technology, field, selector, pattern, kind, message string) {
	state.report.Summary.PatternsSeen++
	state.report.Summary.PatternsSkipped++
	state.report.Issues = append(state.report.Issues, Issue{Kind: kind, Technology: technology, Field: field, Selector: selector, Pattern: pattern, Message: message})
}

func (state *importState) finalize() {
	for technology, definition := range state.database.Technologies {
		if len(definition.Patterns) == 0 {
			delete(state.database.Technologies, technology)
			continue
		}
		sort.Slice(definition.Patterns, func(i, j int) bool {
			left, right := definition.Patterns[i], definition.Patterns[j]
			return left.Channel+"\x00"+left.Selector+"\x00"+strings.Join(left.Origins, "\x01")+"\x00"+left.Regex < right.Channel+"\x00"+right.Selector+"\x00"+strings.Join(right.Origins, "\x01")+"\x00"+right.Regex
		})
		state.database.Technologies[technology] = definition
	}
	state.report.Summary.SourceFiles = len(state.report.SourceFiles)
	state.report.Summary.TechnologiesImported = len(state.database.Technologies)
	sort.Slice(state.report.Issues, func(i, j int) bool {
		left, right := state.report.Issues[i], state.report.Issues[j]
		return left.Technology+"\x00"+left.Field+"\x00"+left.Selector+"\x00"+left.Pattern+"\x00"+left.Kind < right.Technology+"\x00"+right.Field+"\x00"+right.Selector+"\x00"+right.Pattern+"\x00"+right.Kind
	})
}

type mapEntry struct {
	selector string
	patterns []string
}
type countable struct{ selector, pattern string }

func patternList(raw json.RawMessage) ([]string, error) {
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, errors.New("expected a pattern string or string array")
	}
	return many, nil
}

func patternMap(raw json.RawMessage) ([]mapEntry, error) {
	var values map[string]json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, errors.New("expected an object of selector-to-pattern entries")
	}
	selectors := make([]string, 0, len(values))
	for selector := range values {
		selectors = append(selectors, selector)
	}
	sort.Strings(selectors)
	entries := make([]mapEntry, 0, len(selectors))
	for _, selector := range selectors {
		patterns, err := patternList(values[selector])
		if err != nil {
			return nil, fmt.Errorf("selector %q: %w", selector, err)
		}
		entries = append(entries, mapEntry{selector, patterns})
	}
	return entries, nil
}

func countablePatterns(raw json.RawMessage) []countable {
	if patterns, err := patternList(raw); err == nil {
		output := make([]countable, 0, len(patterns))
		for _, pattern := range patterns {
			output = append(output, countable{pattern: pattern})
		}
		return output
	}
	entries, err := patternMap(raw)
	if err != nil {
		return []countable{{pattern: string(raw)}}
	}
	output := make([]countable, 0)
	for _, entry := range entries {
		for _, pattern := range entry.patterns {
			output = append(output, countable{entry.selector, pattern})
		}
	}
	return output
}

func categoryIDs(raw json.RawMessage) ([]string, error) {
	var values []json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, errors.New("expected an array")
	}
	ids := make([]string, 0, len(values))
	for _, value := range values {
		var number json.Number
		if err := json.Unmarshal(value, &number); err == nil {
			ids = append(ids, number.String())
			continue
		}
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			return nil, errors.New("category IDs must be numbers or strings")
		}
		ids = append(ids, text)
	}
	return ids, nil
}

func readCategories(path string) (map[string]string, error) {
	output := make(map[string]string)
	if path == "" {
		return output, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat categories: %w", err)
	}
	if info.Size() > maximumFileBytes {
		return nil, fmt.Errorf("categories file exceeds %d bytes", maximumFileBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read categories: %w", err)
	}
	var values map[string]struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(data, &values); err != nil {
		return nil, fmt.Errorf("decode categories: %w", err)
	}
	for id, value := range values {
		name := strings.TrimSpace(value.Name)
		if name == "" {
			return nil, fmt.Errorf("category %q has no name", id)
		}
		output[id] = name
	}
	return output, nil
}

func sourceFiles(input, categoriesPath string) ([]string, error) {
	info, err := os.Stat(input)
	if err != nil {
		return nil, fmt.Errorf("stat input: %w", err)
	}
	if !info.IsDir() {
		return []string{input}, nil
	}
	entries, err := os.ReadDir(input)
	if err != nil {
		return nil, fmt.Errorf("read input directory: %w", err)
	}
	categoryAbsolute, _ := filepath.Abs(categoriesPath)
	files := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() || strings.ToLower(filepath.Ext(entry.Name())) != ".json" {
			continue
		}
		path := filepath.Join(input, entry.Name())
		absolute, _ := filepath.Abs(path)
		if categoriesPath != "" && absolute == categoryAbsolute {
			continue
		}
		files = append(files, path)
	}
	if len(files) == 0 {
		return nil, errors.New("input directory contains no JSON files")
	}
	sort.Strings(files)
	return files, nil
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	output := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		output = append(output, value)
	}
	sort.Strings(output)
	return output
}
