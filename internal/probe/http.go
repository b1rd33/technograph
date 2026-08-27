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
	"strings"
	"time"

	"github.com/b1rd33/technograph/internal/extract"
	"github.com/b1rd33/technograph/internal/model"
)

const (
	defaultMaxBodyBytes = 2 * 1024 * 1024
	defaultMaxRedirects = 10
	userAgent           = "technograph/1.0 (HTTP-only technology detector)"
)

var errTooManyRedirects = errors.New("maximum redirects exceeded")

// HTTPOptions configures the reusable homepage probe.
type HTTPOptions struct {
	Timeout      time.Duration
	MaxBodyBytes int64
	MaxRedirects int
	InsecureTLS  bool
	Logger       *slog.Logger
	Transport    http.RoundTripper
}

// HTTPProbe fetches final homepage responses using one shared transport and a
// fresh cookie jar per domain.
type HTTPProbe struct {
	timeout      time.Duration
	maxBodyBytes int64
	maxRedirects int
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
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if options.Transport == nil {
		options.Transport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   min(options.Timeout, 5*time.Second),
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          40,
			MaxIdleConnsPerHost:   4,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   min(options.Timeout, 5*time.Second),
			ResponseHeaderTimeout: options.Timeout,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: options.InsecureTLS}, //nolint:gosec -- explicit CLI option
		}
	}
	return &HTTPProbe{
		timeout: options.Timeout, maxBodyBytes: options.MaxBodyBytes,
		maxRedirects: options.MaxRedirects, logger: options.Logger,
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
	result, signals, err := probe.attempt(ctx, httpsURL)
	if err == nil {
		return result, signals
	}
	if ctx.Err() != nil || errors.Is(err, errTooManyRedirects) || !isTransportFailure(err) {
		result.Error = err.Error()
		return result, nil
	}

	httpURL := "http://" + hostname
	result, signals, err = probe.attempt(ctx, httpURL)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}
	return result, signals
}

func (probe *HTTPProbe) attempt(ctx context.Context, target string) (model.HTTPResult, []model.Signal, error) {
	result := model.HTTPResult{RequestedURL: target}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return result, nil, fmt.Errorf("create cookie jar: %w", err)
	}
	redirects := 0
	client := &http.Client{
		Transport: probe.transport,
		Jar:       jar,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			redirects = len(via)
			if len(via) >= probe.maxRedirects {
				return errTooManyRedirects
			}
			return nil
		},
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return result, nil, fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("User-Agent", userAgent)
	request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	request.Header.Set("Accept-Language", "en-US,en;q=0.9")

	response, err := client.Do(request)
	if err != nil {
		return result, nil, fmt.Errorf("request %s: %w", target, err)
	}
	defer response.Body.Close()

	limited := io.LimitReader(response.Body, probe.maxBodyBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return result, nil, fmt.Errorf("read %s: %w", target, err)
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
	signals = append(signals, extract.Cookies(jar.Cookies(response.Request.URL))...)
	result.Blocked, result.Challenge, result.BlockReason = classifyResponse(response.StatusCode, response.Header, body)
	if result.Blocked {
		probe.logger.Warn("HTTP response blocked", "url", result.FinalURL, "reason", result.BlockReason)
	}
	if response.StatusCode < http.StatusBadRequest && !result.Challenge && isHTMLResponse(response.Header.Get("Content-Type"), body) {
		documentSignals, parseErr := extract.Document(body, response.Request.URL)
		if parseErr != nil {
			return result, signals, fmt.Errorf("parse %s: %w", result.FinalURL, parseErr)
		}
		signals = append(signals, documentSignals...)
	}
	return result, signals, nil
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
