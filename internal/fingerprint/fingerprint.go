package fingerprint

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/b1rd33/technograph/internal/model"
)

// Warning describes a pattern skipped while loading a non-strict external
// database.
type Warning struct {
	Technology string
	Channel    model.Channel
	Pattern    string
	Err        error
}

func (warning Warning) Error() string {
	return fmt.Sprintf(
		"%s/%s pattern %q: %v",
		warning.Technology,
		warning.Channel,
		warning.Pattern,
		warning.Err,
	)
}

// Pattern is one compiled fingerprint rule.
type Pattern struct {
	Technology     string
	Channel        model.Channel
	Target         model.Part
	Selector       string
	Origins        []string
	Source         string
	Expression     string
	Confidence     int
	VersionPattern string
	regex          *regexp.Regexp
}

type rawFile struct {
	SchemaVersion int                      `json:"schema_version"`
	Technologies  map[string]rawTechnology `json:"technologies"`
}

type rawTechnology struct {
	Patterns   []rawPattern `json:"patterns"`
	Categories []string     `json:"categories,omitempty"`
}

// UnmarshalJSON accepts the explicit normalized pattern list used by the
// bundled data and the convenient channel: pattern-or-list shape.
func (technology *rawTechnology) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if patterns, ok := fields["patterns"]; ok {
		if err := json.Unmarshal(patterns, &technology.Patterns); err != nil {
			return fmt.Errorf("decode patterns: %w", err)
		}
	}
	if categories, ok := fields["categories"]; ok {
		if err := json.Unmarshal(categories, &technology.Categories); err != nil {
			return fmt.Errorf("decode categories: %w", err)
		}
	}
	if category, ok := fields["category"]; ok {
		var value string
		if err := json.Unmarshal(category, &value); err != nil {
			return fmt.Errorf("decode category: %w", err)
		}
		technology.Categories = append(technology.Categories, value)
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		if key != "patterns" && key != "category" && key != "categories" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, err := model.ParseChannel(key); err != nil {
			continue // permit descriptive Wappalyzer metadata fields
		}
		var one string
		if err := json.Unmarshal(fields[key], &one); err == nil {
			technology.Patterns = append(technology.Patterns, rawPattern{Channel: key, Regex: one})
			continue
		}
		var many []string
		if err := json.Unmarshal(fields[key], &many); err != nil {
			return fmt.Errorf("channel %q must be a pattern or pattern list", key)
		}
		for _, expression := range many {
			technology.Patterns = append(technology.Patterns, rawPattern{Channel: key, Regex: expression})
		}
	}
	return nil
}

type rawPattern struct {
	Channel  string   `json:"channel"`
	Regex    string   `json:"regex"`
	Target   string   `json:"target,omitempty"`
	Selector string   `json:"selector,omitempty"`
	Origins  []string `json:"origins,omitempty"`
}

// Database is an immutable channel-indexed fingerprint set.
type Database struct {
	byChannel  map[model.Channel][]Pattern
	categories map[string][]string
	count      int
}

// Descriptor is the stable, serializable view of one compiled fingerprint.
type Descriptor struct {
	Technology string        `json:"technology"`
	Channel    model.Channel `json:"channel"`
	Target     model.Part    `json:"target"`
	Selector   string        `json:"selector,omitempty"`
	Origins    []string      `json:"origins,omitempty"`
	Pattern    string        `json:"pattern"`
	Confidence int           `json:"confidence"`
	Categories []string      `json:"categories,omitempty"`
}

// Count returns the number of compiled patterns.
func (database *Database) Count() int {
	return database.count
}

// Descriptors returns fingerprints in deterministic technology/channel order.
func (database *Database) Descriptors() []Descriptor {
	descriptors := make([]Descriptor, 0, database.count)
	for _, patterns := range database.byChannel {
		for _, pattern := range patterns {
			descriptors = append(descriptors, Descriptor{
				Technology: pattern.Technology, Channel: pattern.Channel,
				Target: pattern.Target, Pattern: pattern.Source, Confidence: pattern.Confidence,
				Selector:   pattern.Selector,
				Origins:    append([]string(nil), pattern.Origins...),
				Categories: append([]string(nil), database.categories[pattern.Technology]...),
			})
		}
	}
	sort.Slice(descriptors, func(i, j int) bool {
		if descriptors[i].Technology != descriptors[j].Technology {
			return descriptors[i].Technology < descriptors[j].Technology
		}
		if descriptors[i].Channel != descriptors[j].Channel {
			return descriptors[i].Channel < descriptors[j].Channel
		}
		if descriptors[i].Selector != descriptors[j].Selector {
			return descriptors[i].Selector < descriptors[j].Selector
		}
		if descriptors[i].Target != descriptors[j].Target {
			return descriptors[i].Target < descriptors[j].Target
		}
		if strings.Join(descriptors[i].Origins, "\x00") != strings.Join(descriptors[j].Origins, "\x00") {
			return strings.Join(descriptors[i].Origins, "\x00") < strings.Join(descriptors[j].Origins, "\x00")
		}
		return descriptors[i].Pattern < descriptors[j].Pattern
	})
	return descriptors
}

// Categories returns stable category metadata for a technology.
func (database *Database) Categories(technology string) []string {
	return append([]string(nil), database.categories[technology]...)
}

// Load parses and compiles a normalized fingerprint file. Strict mode is used
// for bundled data and rejects any unsupported regex. Non-strict mode skips
// unsupported expressions but returns a warning for every skipped pattern.
func Load(data []byte, strict bool) (*Database, []Warning, error) {
	var source rawFile
	if err := json.Unmarshal(data, &source); err != nil {
		return nil, nil, fmt.Errorf("decode fingerprints: %w", err)
	}
	if source.SchemaVersion != 1 {
		return nil, nil, fmt.Errorf("unsupported fingerprint schema version %d", source.SchemaVersion)
	}
	if len(source.Technologies) == 0 {
		return nil, nil, errors.New("fingerprint database contains no technologies")
	}

	database := &Database{byChannel: make(map[model.Channel][]Pattern), categories: make(map[string][]string)}
	warnings := make([]Warning, 0)
	technologyNames := make([]string, 0, len(source.Technologies))
	for technology := range source.Technologies {
		technologyNames = append(technologyNames, technology)
	}
	sort.Strings(technologyNames)

	for _, technology := range technologyNames {
		definition := source.Technologies[technology]
		categories, err := normalizeCategories(definition.Categories)
		if err != nil {
			return nil, nil, fmt.Errorf("technology %q: %w", technology, err)
		}
		database.categories[technology] = categories
		if len(definition.Patterns) == 0 {
			return nil, nil, fmt.Errorf("technology %q contains no patterns", technology)
		}
		for index, raw := range definition.Patterns {
			channel, err := model.ParseChannel(raw.Channel)
			if err != nil {
				return nil, nil, fmt.Errorf("technology %q pattern %d: %w", technology, index, err)
			}
			selector := strings.TrimSpace(raw.Selector)
			origins, err := normalizeOrigins(raw.Origins)
			if err != nil {
				return nil, nil, fmt.Errorf("technology %q pattern %d: %w", technology, index, err)
			}
			target, err := parseTarget(raw.Target, channel, selector != "")
			if err != nil {
				return nil, nil, fmt.Errorf("technology %q pattern %d: %w", technology, index, err)
			}
			expression, confidence, version, err := parseTags(raw.Regex)
			if err != nil {
				return nil, nil, fmt.Errorf("technology %q pattern %d: %w", technology, index, err)
			}
			if expression == "" && selector == "" {
				return nil, nil, fmt.Errorf("technology %q pattern %d: regex is empty", technology, index)
			}
			compiled, err := regexp.Compile("(?i)" + expression)
			if err != nil {
				warning := Warning{Technology: technology, Channel: channel, Pattern: raw.Regex, Err: err}
				if strict {
					return nil, nil, fmt.Errorf("compile bundled fingerprint: %w", warning)
				}
				warnings = append(warnings, warning)
				continue
			}
			database.byChannel[channel] = append(database.byChannel[channel], Pattern{
				Technology: technology, Channel: channel, Target: target, Selector: selector, Origins: origins,
				Source: raw.Regex, Expression: expression, Confidence: confidence,
				VersionPattern: version, regex: compiled,
			})
			database.count++
		}
	}
	if database.count == 0 {
		return nil, warnings, errors.New("fingerprint database contains no compilable patterns")
	}
	return database, warnings, nil
}

func normalizeOrigins(values []string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	output := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, errors.New("origin cannot be empty")
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		output = append(output, value)
	}
	sort.Strings(output)
	return output, nil
}

func normalizeCategories(values []string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	output := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, errors.New("category cannot be empty")
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		output = append(output, value)
	}
	sort.Strings(output)
	return output, nil
}

func parseTarget(raw string, channel model.Channel, hasSelector bool) (model.Part, error) {
	if raw == "" {
		if hasSelector {
			return model.PartValue, nil
		}
		if channel == model.ChannelHeader || channel == model.ChannelCookie {
			return model.PartName, nil
		}
		return model.PartValue, nil
	}
	target := model.Part(raw)
	if target != model.PartName && target != model.PartValue {
		return "", fmt.Errorf("invalid target %q", raw)
	}
	return target, nil
}

func parseTags(source string) (expression string, confidence int, version string, err error) {
	parts := strings.Split(source, `\;`)
	expressionParts := []string{parts[0]}
	confidence = 100
	for _, part := range parts[1:] {
		key, value, tagged := strings.Cut(part, ":")
		if !tagged || (key != "confidence" && key != "version") {
			expressionParts = append(expressionParts, part)
			continue
		}
		switch key {
		case "confidence":
			parsed, parseErr := strconv.Atoi(value)
			if parseErr != nil || parsed < 0 || parsed > 100 {
				return "", 0, "", fmt.Errorf("invalid confidence %q", value)
			}
			confidence = parsed
		case "version":
			version = value
		}
	}
	return strings.Join(expressionParts, `\;`), confidence, version, nil
}

// ValidateRegex checks Wappalyzer-style pattern tags and RE2 compatibility
// without constructing a database. Importers use it to report unsupported
// patterns individually instead of silently rewriting them.
func ValidateRegex(source string) error {
	expression, _, _, err := parseTags(source)
	if err != nil {
		return err
	}
	if _, err := regexp.Compile("(?i)" + expression); err != nil {
		return err
	}
	return nil
}

// Engine matches structured signals against a compiled database.
type Engine struct {
	database *Database
}

func NewEngine(database *Database) *Engine {
	return &Engine{database: database}
}

// Detect returns sorted technology names and deduplicated evidence.
func (engine *Engine) Detect(signals []model.Signal) ([]string, []model.Evidence) {
	detected := make(map[string]struct{})
	seenEvidence := make(map[string]struct{})
	evidence := make([]model.Evidence, 0)
	for _, signal := range signals {
		for _, pattern := range engine.database.byChannel[signal.Channel] {
			if len(pattern.Origins) > 0 && !contains(pattern.Origins, signal.Origin) {
				continue
			}
			if pattern.Selector != "" && !strings.EqualFold(signal.Name, pattern.Selector) {
				continue
			}
			text := signal.Text(pattern.Target)
			if text == "" && pattern.Selector == "" {
				continue
			}
			location := pattern.regex.FindStringIndex(text)
			if location == nil {
				continue
			}
			match := text[location[0]:location[1]]
			detected[pattern.Technology] = struct{}{}
			key := pattern.Technology + "\x00" + string(pattern.Channel) + "\x00" + pattern.Selector + "\x00" + pattern.Source
			if _, duplicate := seenEvidence[key]; duplicate {
				continue
			}
			seenEvidence[key] = struct{}{}
			evidence = append(evidence, model.Evidence{
				Technology: pattern.Technology,
				Channel:    pattern.Channel,
				Selector:   pattern.Selector,
				Pattern:    pattern.Source,
				Matched:    match,
				Origin:     signal.Origin,
				Confidence: pattern.Confidence,
			})
		}
	}
	technologies := make([]string, 0, len(detected))
	for technology := range detected {
		technologies = append(technologies, technology)
	}
	sort.Strings(technologies)
	sort.Slice(evidence, func(i, j int) bool {
		if evidence[i].Technology != evidence[j].Technology {
			return evidence[i].Technology < evidence[j].Technology
		}
		if evidence[i].Channel != evidence[j].Channel {
			return evidence[i].Channel < evidence[j].Channel
		}
		if evidence[i].Selector != evidence[j].Selector {
			return evidence[i].Selector < evidence[j].Selector
		}
		return evidence[i].Pattern < evidence[j].Pattern
	})
	return technologies, evidence
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
