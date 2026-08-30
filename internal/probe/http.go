package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/b1rd33/technograph/internal/extract"
	"github.com/b1rd33/technograph/internal/model"
	"github.com/b1rd33/technograph/internal/policy"
)

const (
	defaultMaxBodyBytes = 2 * 1024 * 1024
	defaultMaxRedirects = 10
	maximumPageLimit    = 5
	maxResponseHeaderKB = 1 << 20
	maxCookies          = 100
	maxCookieValueLen   = 4096
	maxCookieBytes      = 32 << 10
	userAgent           = "technograph/1.0 (HTTP-only technology detector)"
)

var errTooManyRedirects = errors.New("maximum redirects exceeded")
var errCrossHostRedirect = errors.New("secondary page redirected to another host")

// HTTPOptions configures the reusable homepage probe.
type HTTPOptions struct {
	Timeout      time.Duration
	MaxBodyBytes int64
	MaxRedirects int
	PageLimit    int
	InsecureTLS  bool
	SafeNetwork  bool
	Logger       *slog.Logger
	Transport    http.RoundTripper
}

// HTTPProbe fetches final homepage responses using one shared transport and a
// fresh cookie jar per domain.
type HTTPProbe struct {
	timeout      time.Duration
	maxBodyBytes int64
	maxRedirects int
	pageLimit    int
	logger       *slog.Logger
	transport    http.RoundTripper
}

func NewHTTPProbe(options HTTPOptions) *HTTPProbe {
	if options.Timeout <= 0 {
		options.Timeout = 8 * time.Second
	}
	if options.MaxBodyBytes <= 0 {
		options.MaxBodyBytes = defaultMaxBodyBytes
	}
	if options.MaxRedirects <= 0 {
		options.MaxRedirects = defaultMaxRedirects
	}
	if options.PageLimit <= 0 {
		options.PageLimit = 1
	}
	if options.PageLimit > maximumPageLimit {
		options.PageLimit = maximumPageLimit
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if options.Transport == nil {
		dialer := &net.Dialer{
			Timeout:   min(options.Timeout, 5*time.Second),
			KeepAlive: 30 * time.Second,
		}
		dialContext := dialer.DialContext
		proxy := http.ProxyFromEnvironment
		if options.SafeNetwork {
			dialContext = (policy.SafeDialer{Dialer: dialer}).DialContext
			proxy = nil
		}
		options.Transport = &http.Transport{
			Proxy:                  proxy,
			DialContext:            dialContext,
			ForceAttemptHTTP2:      true,
			MaxIdleConns:           40,
			MaxIdleConnsPerHost:    4,
			IdleConnTimeout:        60 * time.Second,
			TLSHandshakeTimeout:    min(options.Timeout, 5*time.Second),
			ResponseHeaderTimeout:  options.Timeout,
			MaxResponseHeaderBytes: int64(maxResponseHeaderKB),
			TLSClientConfig:        &tls.Config{InsecureSkipVerify: options.InsecureTLS}, //nolint:gosec -- explicit CLI option
		}
	}
	return &HTTPProbe{
		timeout: options.Timeout, maxBodyBytes: options.MaxBodyBytes,
		maxRedirects: options.MaxRedirects, logger: options.Logger,
		pageLimit: options.PageLimit,
		transport: options.Transport,
	}
}

// CloseIdleConnections releases pooled idle sockets after a scan.
func (probe *HTTPProbe) CloseIdleConnections() {
	if closer, ok := probe.transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// Probe fetches a domain homepage. HTTPS is attempted first; plain HTTP is
// tried only when HTTPS fails at the transport or TLS layer.
func (probe *HTTPProbe) Probe(ctx context.Context, hostname string) (model.HTTPResult, []model.Signal) {
	ctx, cancel := context.WithTimeout(ctx, probe.timeout)
	defer cancel()

	httpsURL := "https://" + hostname
	result, signals, links, err := probe.attempt(ctx, httpsURL, "")
	if err == nil {
		return probe.crawl(ctx, result, signals, links)
	}
	if ctx.Err() != nil || errors.Is(err, errTooManyRedirects) || !isTransportFailure(err) {
		result.Error = err.Error()
		return result, nil
	}

	httpURL := "http://" + hostname
	result, signals, links, err = probe.attempt(ctx, httpURL, "")
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}
	return probe.crawl(ctx, result, signals, links)
}

func (probe *HTTPProbe) attempt(ctx context.Context, target, allowedHost string) (model.HTTPResult, []model.Signal, []string, error) {
	result := model.HTTPResult{RequestedURL: target}
	jar := &boundedJar{jar: newJar(), maxCookies: maxCookies, maxCookieBytes: maxCookieBytes}
	redirects := 0
	client := &http.Client{
		Transport: probe.transport,
		Jar:       jar,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			redirects = len(via)
			if len(via) >= probe.maxRedirects {
				return errTooManyRedirects
			}
			if allowedHost != "" && !strings.EqualFold(request.URL.Hostname(), allowedHost) {
				return errCrossHostRedirect
			}
			return nil
		},
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return result, nil, nil, fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("User-Agent", userAgent)
	request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	request.Header.Set("Accept-Language", "en-US,en;q=0.9")

	response, err := client.Do(request)
	if err != nil {
		return result, nil, nil, fmt.Errorf("request %s: %w", target, err)
	}
	defer response.Body.Close()

	limited := io.LimitReader(response.Body, probe.maxBodyBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return result, nil, nil, fmt.Errorf("read %s: %w", target, err)
	}
	if int64(len(body)) > probe.maxBodyBytes {
		body = body[:probe.maxBodyBytes]
		result.BodyTruncated = true
	}

	result.FinalURL = response.Request.URL.String()
	result.StatusCode = response.StatusCode
	result.Redirects = redirects
	result.ContentType = response.Header.Get("Content-Type")
	result.BodyBytes = len(body)

	signals := extract.Headers(response.Header)
	origHeaderCount := len(signals)
	signals = limitHeaders(signals)
	if len(signals) < origHeaderCount {
		result.SignalsTruncated = true
	}
	cookieSignals := extract.Cookies(jar.Cookies(response.Request.URL))
	origCookieCount := len(cookieSignals)
	cookieSignals = limitCookies(cookieSignals)
	if len(cookieSignals) < origCookieCount || jar.Truncated() {
		result.SignalsTruncated = true
	}
	signals = append(signals, cookieSignals...)
	result.Blocked, result.Challenge, result.BlockReason = classifyResponse(response.StatusCode, response.Header, body)
	if result.Blocked {
		probe.logger.Warn("HTTP response blocked", "url", result.FinalURL, "reason", result.BlockReason)
	}
	extractTruncated := false
	links := []string{}
	if response.StatusCode < http.StatusBadRequest && !result.Challenge && isHTMLResponse(response.Header.Get("Content-Type"), body) {
		documentSignals, documentLinks, docTruncated, parseErr := extract.DocumentWithLinks(body, response.Request.URL)
		if parseErr != nil {
			return result, signals, nil, fmt.Errorf("parse %s: %w", result.FinalURL, parseErr)
		}
		extractTruncated = docTruncated
		signals = append(signals, documentSignals...)
		links = documentLinks
	}
	if extractTruncated {
		result.SignalsTruncated = true
	}
	return result, signals, links, nil
}

func (probe *HTTPProbe) crawl(ctx context.Context, result model.HTTPResult, signals []model.Signal, links []string) (model.HTTPResult, []model.Signal) {
	if result.FinalURL == "" {
		return result, signals
	}
	if probe.pageLimit <= 1 {
		return result, signals
	}
	result.PageCount = 1
	tagPageSignals(signals, result.FinalURL)
	if result.Blocked {
		return result, signals
	}
	primary, err := url.Parse(result.FinalURL)
	if err != nil || primary.Hostname() == "" {
		return result, signals
	}
	host := primary.Hostname()
	seen := map[string]struct{}{}
	if normalized := normalizeCrawlURL(result.FinalURL, host); normalized != "" {
		seen[normalized] = struct{}{}
	}
	queue := make([]string, 0)
	queued := make(map[string]struct{})
	addLinks := func(values []string) {
		for _, value := range values {
			normalized := normalizeCrawlURL(value, host)
			if normalized == "" {
				continue
			}
			if _, exists := seen[normalized]; exists {
				continue
			}
			if _, exists := queued[normalized]; exists {
				continue
			}
			queued[normalized] = struct{}{}
			queue = append(queue, normalized)
		}
		sort.Slice(queue, func(i, j int) bool {
			left, right := crawlPriority(queue[i]), crawlPriority(queue[j])
			if left != right {
				return left < right
			}
			return queue[i] < queue[j]
		})
	}
	addLinks(links)
	for result.PageCount < probe.pageLimit && len(queue) > 0 && ctx.Err() == nil {
		target := queue[0]
		queue = queue[1:]
		delete(queued, target)
		if _, exists := seen[target]; exists {
			continue
		}
		seen[target] = struct{}{}
		page, pageSignals, pageLinks, err := probe.attempt(ctx, target, host)
		if err != nil {
			page.Error = err.Error()
		}
		result.Pages = append(result.Pages, secondaryPage(page))
		result.PageCount++
		if page.SignalsTruncated {
			result.SignalsTruncated = true
		}
		if err != nil {
			continue
		}
		if normalized := normalizeCrawlURL(page.FinalURL, host); normalized != "" {
			seen[normalized] = struct{}{}
		}
		tagPageSignals(pageSignals, page.FinalURL)
		signals = append(signals, pageSignals...)
		addLinks(pageLinks)
	}
	return result, signals
}

func tagPageSignals(signals []model.Signal, pageURL string) {
	for index := range signals {
		signals[index].PageURL = pageURL
	}
}

func secondaryPage(result model.HTTPResult) model.HTTPPageResult {
	return model.HTTPPageResult{
		RequestedURL: result.RequestedURL, FinalURL: result.FinalURL,
		StatusCode: result.StatusCode, Redirects: result.Redirects,
		ContentType: result.ContentType, BodyBytes: result.BodyBytes,
		BodyTruncated: result.BodyTruncated, SignalsTruncated: result.SignalsTruncated, Blocked: result.Blocked,
		Challenge: result.Challenge, BlockReason: result.BlockReason, Error: result.Error,
	}
}

func normalizeCrawlURL(value, allowedHost string) string {
	parsed, err := url.Parse(value)
	if err != nil || (!strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https")) || parsed.User != nil {
		return ""
	}
	if !strings.EqualFold(parsed.Hostname(), allowedHost) {
		return ""
	}
	port := parsed.Port()
	if port != "" && port != "80" && port != "443" {
		return ""
	}
	cleanedPath := path.Clean(parsed.Path)
	if cleanedPath == "." || cleanedPath == "" {
		cleanedPath = "/"
	}
	if len(cleanedPath) > 512 || excludedCrawlExtension(cleanedPath) {
		return ""
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	if (parsed.Scheme == "https" && port == "443") || (parsed.Scheme == "http" && port == "80") {
		parsed.Host = strings.ToLower(parsed.Hostname())
	}
	parsed.Path = cleanedPath
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	return parsed.String()
}

func excludedCrawlExtension(value string) bool {
	extension := strings.ToLower(path.Ext(value))
	switch extension {
	case ".7z", ".avi", ".css", ".csv", ".doc", ".docx", ".gif", ".gz", ".ico", ".jpeg", ".jpg", ".js", ".json", ".map", ".mov", ".mp3", ".mp4", ".pdf", ".png", ".rar", ".rss", ".svg", ".tar", ".tgz", ".txt", ".webm", ".webp", ".xml", ".zip":
		return true
	default:
		return false
	}
}

func crawlPriority(value string) int {
	lower := strings.ToLower(value)
	keywords := []string{"/pricing", "/integrations", "/features", "/products", "/solutions", "/customers", "/about", "/contact"}
	for index, keyword := range keywords {
		if strings.Contains(lower, keyword) {
			return index
		}
	}
	return len(keywords) + strings.Count(lower, "/")
}

func classifyResponse(status int, headers http.Header, body []byte) (blocked, challenge bool, reason string) {
	lowerBody := strings.ToLower(string(body))
	markers := []string{
		"/cdn-cgi/challenge-platform", "cf-chl-", "cf_chl_", "just a moment...",
		"checking your browser", "verify you are human", "verify you are a human",
		"enable javascript and cookies to continue", "captcha-delivery.com",
	}
	for _, marker := range markers {
		if strings.Contains(lowerBody, marker) {
			return true, true, "challenge marker " + marker
		}
	}
	if strings.EqualFold(headers.Get("cf-mitigated"), "challenge") {
		return true, true, "cf-mitigated challenge"
	}
	switch status {
	case http.StatusUnauthorized:
		return true, false, "HTTP 401 unauthorized"
	case http.StatusForbidden:
		return true, false, "HTTP 403 access denied"
	case http.StatusTooManyRequests:
		return true, false, "HTTP 429 rate limited"
	case http.StatusUnavailableForLegalReasons:
		return true, false, "HTTP 451 unavailable for legal reasons"
	}
	return false, false, ""
}

func isHTMLResponse(contentType string, body []byte) bool {
	if contentType != "" {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err == nil {
			return mediaType == "text/html" || mediaType == "application/xhtml+xml"
		}
		return false
	}
	detected := http.DetectContentType(body[:min(len(body), 512)])
	mediaType, _, err := mime.ParseMediaType(detected)
	return err == nil && (mediaType == "text/html" || mediaType == "application/xhtml+xml")
}

func isTransportFailure(err error) bool {
	if strings.Contains(err.Error(), "server gave HTTP response to HTTPS client") {
		return true
	}
	var urlError *url.Error
	if errors.As(err, &urlError) {
		err = urlError.Err
	}
	var networkError net.Error
	if errors.As(err, &networkError) {
		return true
	}
	var recordHeaderError tls.RecordHeaderError
	if errors.As(err, &recordHeaderError) {
		return true
	}
	var authorityError x509.UnknownAuthorityError
	if errors.As(err, &authorityError) {
		return true
	}
	var hostnameError x509.HostnameError
	if errors.As(err, &hostnameError) {
		return true
	}
	var certificateError x509.CertificateInvalidError
	return errors.As(err, &certificateError)
}

func limitCookies(signals []model.Signal) []model.Signal {
	if len(signals) <= maxCookies {
		total := 0
		for _, s := range signals {
			total += len(s.Value)
		}
		if total <= maxCookieBytes {
			need := false
			for _, s := range signals {
				if len(s.Value) > maxCookieValueLen {
					need = true
					break
				}
			}
			if !need {
				return signals
			}
		}
	}
	limited := make([]model.Signal, 0, min(len(signals), maxCookies))
	total := 0
	for _, s := range signals {
		if len(limited) >= maxCookies {
			break
		}
		if len(s.Value) > maxCookieValueLen {
			s.Value = s.Value[:maxCookieValueLen]
		}
		if total+len(s.Value) > maxCookieBytes {
			break
		}
		total += len(s.Value)
		limited = append(limited, s)
	}
	return limited
}

func limitHeaders(signals []model.Signal) []model.Signal {
	if len(signals) <= 128 {
		return signals
	}
	return signals[:128]
}

func newJar() http.CookieJar {
	jar, _ := cookiejar.New(nil)
	return jar
}

type boundedJar struct {
	jar            http.CookieJar
	maxCookies     int
	maxCookieBytes int
	admittedCount  int
	admittedBytes  int
	truncated      bool
}

func (jar *boundedJar) Truncated() bool {
	return jar.truncated
}

func (jar *boundedJar) Cookies(u *url.URL) []*http.Cookie {
	if jar.jar == nil {
		return nil
	}
	return jar.jar.Cookies(u)
}

func (jar *boundedJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	if jar.jar == nil {
		return
	}
	if jar.admittedCount >= jar.maxCookies || jar.admittedBytes >= jar.maxCookieBytes {
		if len(cookies) > 0 {
			jar.truncated = true
		}
		return
	}
	allowed := make([]*http.Cookie, 0, len(cookies))
	for _, c := range cookies {
		if jar.admittedCount >= jar.maxCookies {
			jar.truncated = true
			break
		}
		sizeValue := c.Value
		if len(sizeValue) > maxCookieValueLen {
			sizeValue = sizeValue[:maxCookieValueLen]
		}
		cookieSize := len(c.Name) + len(c.Domain) + len(c.Path) + len(sizeValue)
		if jar.admittedBytes+cookieSize > jar.maxCookieBytes {
			jar.truncated = true
			break
		}
		didTruncateValue := len(c.Value) > maxCookieValueLen
		if didTruncateValue {
			clone := *c
			clone.Value = clone.Value[:maxCookieValueLen]
			c = &clone
			jar.truncated = true
		}
		allowed = append(allowed, c)
		jar.admittedCount++
		jar.admittedBytes += len(c.Name) + len(c.Domain) + len(c.Path) + len(c.Value)
	}
	if len(allowed) == 0 {
		return
	}
	jar.jar.SetCookies(u, allowed)
}
