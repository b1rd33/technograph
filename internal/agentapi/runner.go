package agentapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/b1rd33/technograph/internal/app"
	"github.com/b1rd33/technograph/internal/domain"
	"github.com/b1rd33/technograph/internal/model"
)

const DefaultMaxDomains = 20

type Runner struct {
	Service    *app.Service
	MaxDomains int
	Now        func() time.Time
}

type preparedInput struct {
	input  string
	index  int
	domain model.Domain
	err    error
}

func (runner Runner) prepare(inputs []string) ([]preparedInput, error) {
	if len(inputs) == 0 {
		return nil, errors.New("no domains supplied")
	}
	maximum := runner.MaxDomains
	if maximum <= 0 {
		maximum = DefaultMaxDomains
	}
	if len(inputs) > maximum {
		return nil, fmt.Errorf("too many domains: got %d, maximum is %d", len(inputs), maximum)
	}
	prepared := make([]preparedInput, len(inputs))
	for index, input := range inputs {
		parsed, err := domain.Parse(input)
		prepared[index] = preparedInput{input: input, index: index, domain: parsed, err: err}
	}
	return prepared, nil
}

// Validate performs input validation without network access.
func (runner Runner) Validate(inputs []string) ([]DomainResult, error) {
	prepared, err := runner.prepare(inputs)
	if err != nil {
		return nil, err
	}
	results := make([]DomainResult, len(prepared))
	for _, item := range prepared {
		results[item.index] = validationResult(item)
	}
	return results, nil
}

// Scan returns a stable ordered report.
func (runner Runner) Scan(ctx context.Context, requestID string, inputs []string) (Report, error) {
	prepared, err := runner.prepare(inputs)
	if err != nil {
		return Report{}, err
	}
	requestID = normalizeRequestID(requestID)
	results := make([]DomainResult, len(prepared))
	validDomains := make([]model.Domain, 0, len(prepared))
	validIndexes := make([]int, 0, len(prepared))
	for _, item := range prepared {
		if item.err != nil {
			results[item.index] = validationResult(item)
			continue
		}
		validDomains = append(validDomains, item.domain)
		validIndexes = append(validIndexes, item.index)
	}
	if len(validDomains) > 0 {
		scanned := runner.Service.Scan(ctx, validDomains)
		for index, result := range scanned {
			original := validIndexes[index]
			results[original] = runner.convertResult(original, prepared[original].input, result)
		}
	}
	return Report{
		SchemaVersion: SchemaVersion, RequestID: requestID, GeneratedAt: runner.now(),
		Results: results, Summary: summarize(results),
	}, nil
}

// ScanStream emits invalid inputs immediately and valid domains in completion
// order. Callers can encode each result without waiting for the whole batch.
func (runner Runner) ScanStream(ctx context.Context, requestID string, inputs []string) (string, <-chan DomainResult, error) {
	prepared, err := runner.prepare(inputs)
	if err != nil {
		return "", nil, err
	}
	requestID = normalizeRequestID(requestID)
	results := make(chan DomainResult, len(prepared))
	go func() {
		defer close(results)
		validDomains := make([]model.Domain, 0, len(prepared))
		validIndexes := make([]int, 0, len(prepared))
		for _, item := range prepared {
			if item.err != nil {
				results <- validationResult(item)
				continue
			}
			validDomains = append(validDomains, item.domain)
			validIndexes = append(validIndexes, item.index)
		}
		for completed := range runner.Service.ScanStream(ctx, validDomains) {
			original := validIndexes[completed.Index]
			results <- runner.convertResult(original, prepared[original].input, completed.Result)
		}
	}()
	return requestID, results, nil
}

func validationResult(item preparedInput) DomainResult {
	result := DomainResult{
		InputIndex: item.index, Input: item.input, Technologies: []string{},
		Warnings: []Issue{}, Errors: []Issue{},
	}
	if item.err != nil {
		result.Status = StatusInvalid
		result.Errors = append(result.Errors, Issue{Code: "INVALID_DOMAIN", Message: item.err.Error()})
		return result
	}
	result.Status = StatusOK
	result.Domain = item.domain.Hostname
	result.Apex = item.domain.Apex
	return result
}

func (runner Runner) convertResult(index int, input string, scanned model.ScanResult) DomainResult {
	result := DomainResult{
		InputIndex: index, Input: input, Domain: scanned.Domain.Hostname, Apex: scanned.Domain.Apex,
		Status: StatusOK, Technologies: nonNil(scanned.Technologies), Evidence: scanned.Evidence,
		HTTP: &scanned.HTTP, DNS: &scanned.DNS, Warnings: []Issue{}, Errors: []Issue{},
		ElapsedMS: scanned.ElapsedMS,
	}
	result.TechnologyCategories = runner.Service.CategoriesFor(result.Technologies)
	if scanned.HTTP.BodyTruncated {
		result.Warnings = append(result.Warnings, Issue{Code: "BODY_TRUNCATED", Message: "response body exceeded the configured limit", Channel: "http"})
	}
	if scanned.HTTP.Blocked || scanned.HTTP.Challenge {
		result.Status = StatusBlocked
		message := scanned.HTTP.BlockReason
		if message == "" {
			message = "the homepage response was blocked"
		}
		result.Warnings = append(result.Warnings, Issue{Code: "HTTP_BLOCKED", Message: message, Channel: "http"})
	}
	if scanned.HTTP.Error != "" {
		result.Errors = append(result.Errors, Issue{Code: "HTTP_FETCH_FAILED", Message: scanned.HTTP.Error, Channel: "http"})
		result.Status = StatusPartial
	}
	for _, page := range scanned.HTTP.Pages {
		if page.BodyTruncated {
			result.Warnings = append(result.Warnings, Issue{Code: "PAGE_BODY_TRUNCATED", Message: "secondary response body exceeded the configured limit: " + page.RequestedURL, Channel: "http_page"})
		}
		if page.Blocked || page.Challenge {
			message := page.BlockReason
			if message == "" {
				message = "secondary page was blocked"
			}
			result.Warnings = append(result.Warnings, Issue{Code: "PAGE_BLOCKED", Message: page.RequestedURL + ": " + message, Channel: "http_page"})
			if result.Status == StatusOK {
				result.Status = StatusPartial
			}
		}
		if page.Error != "" {
			result.Errors = append(result.Errors, Issue{Code: "PAGE_FETCH_FAILED", Message: page.RequestedURL + ": " + page.Error, Channel: "http_page"})
			if result.Status == StatusOK {
				result.Status = StatusPartial
			}
		}
	}
	dnsFailures := 0
	keys := make([]string, 0, len(scanned.DNS.Errors))
	for channel := range scanned.DNS.Errors {
		keys = append(keys, channel)
	}
	sort.Strings(keys)
	for _, channel := range keys {
		dnsFailures++
		result.Errors = append(result.Errors, Issue{
			Code: "DNS_QUERY_FAILED", Message: scanned.DNS.Errors[channel], Channel: "dns_" + channel,
		})
	}
	if dnsFailures > 0 && result.Status == StatusOK {
		result.Status = StatusPartial
	}
	if scanned.HTTP.Error != "" && dnsFailures >= 3 {
		result.Status = StatusFailed
	}
	return result
}

func summarize(results []DomainResult) Summary {
	summary := Summary{Requested: len(results)}
	for _, result := range results {
		summary.Detections += len(result.Technologies)
		switch result.Status {
		case StatusOK:
			summary.OK++
		case StatusPartial:
			summary.Partial++
		case StatusBlocked:
			summary.Blocked++
		case StatusFailed:
			summary.Failed++
		case StatusInvalid:
			summary.Invalid++
		}
	}
	return summary
}

func (runner Runner) now() time.Time {
	if runner.Now != nil {
		return runner.Now().UTC()
	}
	return time.Now().UTC()
}

func normalizeRequestID(value string) string {
	if trimmed := strings.TrimSpace(value); trimmed != "" {
		return trimmed
	}
	random := make([]byte, 12)
	if _, err := rand.Read(random); err == nil {
		return hex.EncodeToString(random)
	}
	return fmt.Sprintf("scan-%d", time.Now().UnixNano())
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
