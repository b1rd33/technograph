package agentcli

import (
	"bytes"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/b1rd33/technograph/internal/fingerprint"
	"github.com/b1rd33/technograph/internal/model"
)

func filterDescriptors(descriptors []fingerprint.Descriptor, technologies, channels []string) ([]fingerprint.Descriptor, error) {
	channelSet := make(map[model.Channel]struct{}, len(channels))
	for _, raw := range channels {
		channel, err := model.ParseChannel(raw)
		if err != nil {
			return nil, fmt.Errorf("unsupported channel %q", raw)
		}
		channelSet[channel] = struct{}{}
	}
	filtered := make([]fingerprint.Descriptor, 0, len(descriptors))
	for _, d := range descriptors {
		if len(technologies) > 0 {
			matched := false
			for _, t := range technologies {
				if strings.EqualFold(d.Technology, t) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		if len(channelSet) > 0 {
			if _, ok := channelSet[d.Channel]; !ok {
				continue
			}
		}
		filtered = append(filtered, d)
	}
	return filtered, nil
}

func renderFingerprintTable(descriptors []fingerprint.Descriptor) []byte {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "TECHNOLOGY\tCHANNEL\tTARGET\tSELECTOR\tORIGINS\tPATTERN\tCONFIDENCE\tCATEGORIES")
	for _, d := range descriptors {
		origins := strings.Join(d.Origins, ", ")
		categories := strings.Join(d.Categories, ", ")
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
			sanitizeTableCell(d.Technology),
			sanitizeTableCell(string(d.Channel)),
			sanitizeTableCell(string(d.Target)),
			sanitizeTableCell(d.Selector),
			sanitizeTableCell(origins),
			sanitizeTableCell(d.Pattern),
			d.Confidence,
			sanitizeTableCell(categories),
		)
	}
	_ = w.Flush()
	return buf.Bytes()
}

func sanitizeTableCell(value string) string {
	value = strings.ReplaceAll(value, "\t", " ")
	value = strings.ReplaceAll(value, "\r\n", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	return value
}
