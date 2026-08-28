package agentcli

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"unicode/utf8"

	"github.com/b1rd33/technograph/internal/agentapi"
)

func renderTable(report agentapi.Report) []byte {
	var buffer bytes.Buffer
	writer := tabwriter.NewWriter(&buffer, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "DOMAIN\tSTATUS\tTECHNOLOGIES\tCATEGORIES\tTIME")
	for _, result := range report.Results {
		domain := result.Domain
		if domain == "" {
			domain = result.Input
		}
		technologies := "—"
		if len(result.Technologies) > 0 {
			technologies = strings.Join(result.Technologies, ", ")
		}
		categories := strings.Join(uniqueCategories(result), ", ")
		if categories == "" {
			categories = "—"
		}
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n",
			truncateText(safeText(domain), 36), strings.ToUpper(string(result.Status)),
			truncateText(safeText(technologies), 54), truncateText(safeText(categories), 38),
			formatMilliseconds(result.ElapsedMS))
	}
	_ = writer.Flush()
	fmt.Fprintf(&buffer, "\n%d domains, %d detections: %d ok, %d partial, %d blocked, %d failed, %d invalid\n",
		report.Summary.Requested, report.Summary.Detections, report.Summary.OK, report.Summary.Partial,
		report.Summary.Blocked, report.Summary.Failed, report.Summary.Invalid)
	return buffer.Bytes()
}

func renderCSV(report agentapi.Report) ([]byte, error) {
	var buffer bytes.Buffer
	writeCSVRecord(&buffer, []string{
		"domain", "status", "technologies", "categories", "http_status", "final_url",
		"dns_mx_status", "dns_txt_status", "dns_cname_status", "elapsed_ms", "issues",
	})
	for _, result := range report.Results {
		domain := result.Domain
		if domain == "" {
			domain = result.Input
		}
		httpStatus, finalURL := "", ""
		if result.HTTP != nil {
			if result.HTTP.StatusCode > 0 {
				httpStatus = strconv.Itoa(result.HTTP.StatusCode)
			}
			finalURL = result.HTTP.FinalURL
		}
		record := []string{
			domain, string(result.Status), strings.Join(result.Technologies, "; "),
			strings.Join(uniqueCategories(result), "; "), httpStatus, finalURL,
			dnsRecordStatus(result, "mx"), dnsRecordStatus(result, "txt"), dnsRecordStatus(result, "cname"),
			strconv.FormatInt(result.ElapsedMS, 10), joinIssues(result),
		}
		for index := range record {
			record[index] = safeCSVCell(safeText(record[index]))
		}
		writeCSVRecord(&buffer, record)
	}
	return buffer.Bytes(), nil
}

func writeCSVRecord(buffer *bytes.Buffer, record []string) {
	for index, value := range record {
		if index > 0 {
			buffer.WriteByte(',')
		}
		if strings.ContainsAny(value, ",\"\r\n") {
			buffer.WriteByte('"')
			buffer.WriteString(strings.ReplaceAll(value, "\"", "\"\""))
			buffer.WriteByte('"')
		} else {
			buffer.WriteString(value)
		}
	}
	buffer.WriteByte('\n')
}

func uniqueCategories(result agentapi.DomainResult) []string {
	seen := make(map[string]struct{})
	values := make([]string, 0)
	for _, technology := range result.Technologies {
		for _, category := range result.TechnologyCategories[technology] {
			if _, exists := seen[category]; exists {
				continue
			}
			seen[category] = struct{}{}
			values = append(values, category)
		}
	}
	sort.Strings(values)
	return values
}

func dnsRecordStatus(result agentapi.DomainResult, recordType string) string {
	if result.DNS == nil {
		return ""
	}
	return result.DNS.Status[recordType]
}

func joinIssues(result agentapi.DomainResult) string {
	values := make([]string, 0, len(result.Warnings)+len(result.Errors))
	for _, issue := range result.Warnings {
		values = append(values, issue.Code+": "+issue.Message)
	}
	for _, issue := range result.Errors {
		values = append(values, issue.Code+": "+issue.Message)
	}
	return strings.Join(values, "; ")
}

func safeCSVCell(value string) string {
	trimmed := strings.TrimLeft(value, " \t\r\n")
	if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + value
	}
	return value
}

func truncateText(value string, maximum int) string {
	if utf8.RuneCountInString(value) <= maximum {
		return value
	}
	runes := []rune(value)
	return string(runes[:maximum-1]) + "…"
}

func formatMilliseconds(value int64) string {
	if value < 1000 {
		return fmt.Sprintf("%dms", value)
	}
	return fmt.Sprintf("%.2fs", float64(value)/1000)
}
