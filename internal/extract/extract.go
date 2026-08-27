package extract

import (
	"bytes"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/christiannikolov/technograph/internal/model"
	"golang.org/x/net/html"
)

const maxInlineScriptBytes = 256 * 1024

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

// Document statically extracts raw HTML, script URLs, inline source, meta
// fields, and syntactic window.* references. JavaScript is never executed.
func Document(body []byte, baseURL *url.URL) ([]model.Signal, error) {
	document, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	signals := []model.Signal{{
		Channel: model.ChannelHTML,
		Value:   string(body),
		Origin:  "html:body",
	}}
	windowNames := make(map[string]struct{})

	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode {
			switch strings.ToLower(node.Data) {
			case "script":
				source := attribute(node, "src")
				if source != "" {
					signals = append(signals, model.Signal{
						Channel: model.ChannelScript,
						Value:   source,
						Origin:  "html:script-src",
					})
					if resolved := resolveScriptURL(baseURL, source); resolved != "" && resolved != source {
						signals = append(signals, model.Signal{
							Channel: model.ChannelScript,
							Value:   resolved,
							Origin:  "html:script-src-absolute",
						})
					}
				} else {
					script := boundedText(node, maxInlineScriptBytes)
					if script != "" {
						signals = append(signals, model.Signal{
							Channel: model.ChannelScript,
							Value:   script,
							Origin:  "html:inline-script",
						})
						collectWindowNames(script, windowNames)
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
				if name != "" || content != "" {
					signals = append(signals, model.Signal{
						Channel: model.ChannelMeta,
						Name:    strings.ToLower(name),
						Value:   content,
						Origin:  "html:meta",
					})
				}
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
		signals = append(signals, model.Signal{
			Channel: model.ChannelJS,
			Name:    name,
			Value:   "window." + name,
			Origin:  "html:window-global-syntax",
		})
	}
	return signals, nil
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

func collectWindowNames(script string, names map[string]struct{}) {
	for _, match := range windowDot.FindAllStringSubmatch(script, -1) {
		names[match[1]] = struct{}{}
	}
	for _, match := range windowBracket.FindAllStringSubmatch(script, -1) {
		names[match[1]] = struct{}{}
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
