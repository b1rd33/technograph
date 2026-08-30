package extract

import (
	"bytes"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/b1rd33/technograph/internal/model"
	"golang.org/x/net/html"
)

const maxInlineScriptBytes = 256 * 1024

const (
	maxLinksPerPage   = 5000
	maxSignalsPerPage = 5000
	maxInlineScripts  = 50
	maxWindowNames    = 512
)

var (
	windowDot     = regexp.MustCompile(`\bwindow\s*\.\s*([A-Za-z_$][A-Za-z0-9_$]*)`)
	windowBracket = regexp.MustCompile(`\bwindow\s*\[\s*["']([^"'\]]{1,100})["']\s*\]`)
)

// Headers converts final-response headers into separate name and value
// signals. Header names are normalized because HTTP field names are
// case-insensitive; values preserve their original text.
func Headers(headers http.Header) []model.Signal {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	signals := make([]model.Signal, 0, len(headers)*2)
	for _, name := range names {
		normalized := strings.ToLower(name)
		values := append([]string(nil), headers[name]...)
		sort.Strings(values)
		for _, value := range values {
			signals = append(signals, model.Signal{
				Channel: model.ChannelHeader,
				Name:    normalized,
				Value:   value,
				Origin:  "http:final-header",
			})
		}
		if len(values) == 0 {
			signals = append(signals, model.Signal{
				Channel: model.ChannelHeader,
				Name:    normalized,
				Origin:  "http:final-header",
			})
		}
	}
	return signals
}

// Cookies converts cookies applicable to the final URL into structured
// signals. Duplicate name/value pairs are removed.
func Cookies(cookies []*http.Cookie) []model.Signal {
	sorted := append([]*http.Cookie(nil), cookies...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Name != sorted[j].Name {
			return sorted[i].Name < sorted[j].Name
		}
		return sorted[i].Value < sorted[j].Value
	})
	seen := make(map[string]struct{})
	signals := make([]model.Signal, 0, len(sorted))
	for _, cookie := range sorted {
		if cookie == nil || cookie.Name == "" {
			continue
		}
		key := cookie.Name + "\x00" + cookie.Value
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		signals = append(signals, model.Signal{
			Channel: model.ChannelCookie,
			Name:    cookie.Name,
			Value:   cookie.Value,
			Origin:  "http:final-cookie",
		})
	}
	return signals
}

// DocumentWithLinksDetailed is like DocumentWithLinks but also returns
// deterministic truncation reasons when truncated.
func DocumentWithLinksDetailed(body []byte, baseURL *url.URL) ([]model.Signal, []string, bool, []model.TruncationReason, error) {
	return documentWithLinksInternal(body, baseURL)
}

// Document statically extracts raw HTML, script URLs, inline source, meta
// fields, and syntactic window.* references. JavaScript is never executed.
func Document(body []byte, baseURL *url.URL) ([]model.Signal, error) {
	signals, _, _, _, err := DocumentWithLinksDetailed(body, baseURL)
	return signals, err
}

// DocumentWithLinks extracts the same static signals plus resolved anchor URLs
// for the bounded opt-in crawler. It does not fetch or execute anything.
func DocumentWithLinks(body []byte, baseURL *url.URL) ([]model.Signal, []string, bool, error) {
	signals, links, truncated, _, err := DocumentWithLinksDetailed(body, baseURL)
	return signals, links, truncated, err
}

func documentWithLinksInternal(body []byte, baseURL *url.URL) ([]model.Signal, []string, bool, []model.TruncationReason, error) {
	document, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, nil, false, nil, err
	}
	signals := []model.Signal{{
		Channel: model.ChannelHTML,
		Value:   string(body),
		Origin:  "html:body",
	}}
	windowNames := make(map[string]struct{})
	links := make([]string, 0)
	truncated := false
	reasons := make(map[model.TruncationReason]struct{})
	addReason := func(r model.TruncationReason) {
		truncated = true
		reasons[r] = struct{}{}
	}

	var walk func(*html.Node)
	inlineCount := 0
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode {
			switch strings.ToLower(node.Data) {
			case "a":
				rawHref := attribute(node, "href")
				if strings.TrimSpace(rawHref) == "" {
					break
				}
				resolved := resolveDocumentURL(baseURL, rawHref)
				if resolved == "" {
					break
				}
				if len(links) >= maxLinksPerPage {
					addReason(model.ReasonLinks)
				} else {
					links = append(links, resolved)
				}
			case "script":
				source := attribute(node, "src")
				if source != "" {
					if len(signals) >= maxSignalsPerPage {
						addReason(model.ReasonSignals)
						break
					}
					signals = append(signals, model.Signal{
						Channel: model.ChannelScript,
						Value:   source,
						Origin:  "html:script-src",
					})
					candidate := resolveScriptURL(baseURL, source)
					if candidate == "" || candidate == source {
						break
					}
					if len(signals) >= maxSignalsPerPage {
						addReason(model.ReasonSignals)
						break
					}
					signals = append(signals, model.Signal{
						Channel: model.ChannelScript,
						Value:   candidate,
						Origin:  "html:script-src-absolute",
					})
				} else {
					script := boundedText(node, maxInlineScriptBytes)
					if script == "" {
						break
					}
					if inlineCount >= maxInlineScripts {
						addReason(model.ReasonInlineScripts)
					}
					if len(signals) >= maxSignalsPerPage {
						addReason(model.ReasonSignals)
					}
					if inlineCount >= maxInlineScripts || len(signals) >= maxSignalsPerPage {
						break
					}
					inlineCount++
					signals = append(signals, model.Signal{
						Channel: model.ChannelScript,
						Value:   script,
						Origin:  "html:inline-script",
					})
					if collectWindowNames(script, windowNames) {
						addReason(model.ReasonWindowNames)
					}
				}
			case "meta":
				name := firstNonEmpty(
					attribute(node, "name"),
					attribute(node, "property"),
					attribute(node, "http-equiv"),
					attribute(node, "itemprop"),
				)
				content := attribute(node, "content")
				if name == "" && content == "" {
					break
				}
				if len(signals) >= maxSignalsPerPage {
					addReason(model.ReasonSignals)
					break
				}
				signals = append(signals, model.Signal{
					Channel: model.ChannelMeta,
					Name:    strings.ToLower(name),
					Value:   content,
					Origin:  "html:meta",
				})
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(document)

	names := make([]string, 0, len(windowNames))
	for name := range windowNames {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if len(signals) >= maxSignalsPerPage {
			addReason(model.ReasonSignals)
			break
		}
		signals = append(signals, model.Signal{
			Channel: model.ChannelJS,
			Name:    name,
			Value:   "window." + name,
			Origin:  "html:window-global-syntax",
		})
	}
	if !truncated {
		return signals, links, false, nil, nil
	}
	sorted := make([]model.TruncationReason, 0, len(reasons))
	for r := range reasons {
		sorted = append(sorted, r)
	}
	sort.Slice(sorted, func(i, j int) bool { return string(sorted[i]) < string(sorted[j]) })
	return signals, links, true, sorted, nil
}

func attribute(node *html.Node, key string) string {
	for _, attribute := range node.Attr {
		if strings.EqualFold(attribute.Key, key) {
			return strings.TrimSpace(attribute.Val)
		}
	}
	return ""
}

func resolveScriptURL(baseURL *url.URL, source string) string {
	return resolveDocumentURL(baseURL, source)
}

func resolveDocumentURL(baseURL *url.URL, source string) string {
	if baseURL == nil {
		return ""
	}
	reference, err := url.Parse(source)
	if err != nil {
		return ""
	}
	return baseURL.ResolveReference(reference).String()
}

func boundedText(node *html.Node, limit int) string {
	var builder strings.Builder
	var collect func(*html.Node)
	collect = func(current *html.Node) {
		if builder.Len() >= limit {
			return
		}
		if current.Type == html.TextNode {
			remaining := limit - builder.Len()
			text := current.Data
			if len(text) > remaining {
				text = text[:remaining]
			}
			builder.WriteString(text)
		}
		for child := current.FirstChild; child != nil; child = child.NextSibling {
			collect(child)
		}
	}
	collect(node)
	return strings.TrimSpace(builder.String())
}

func collectWindowNames(script string, names map[string]struct{}) bool {
	truncated := false
	for _, match := range windowDot.FindAllStringSubmatch(script, -1) {
		key := match[1]
		if _, exists := names[key]; exists {
			continue
		}
		if len(names) >= maxWindowNames {
			truncated = true
			continue
		}
		names[key] = struct{}{}
	}
	for _, match := range windowBracket.FindAllStringSubmatch(script, -1) {
		key := match[1]
		if _, exists := names[key]; exists {
			continue
		}
		if len(names) >= maxWindowNames {
			truncated = true
			continue
		}
		names[key] = struct{}{}
	}
	return truncated
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
