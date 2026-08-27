package probe

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/b1rd33/technograph/internal/model"
)

func TestHTTPProbeExtractsFinalSignals(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.UserAgent() != userAgent {
			t.Errorf("User-Agent = %q", request.UserAgent())
		}
		writer.Header().Set("CF-Ray", "abc")
		http.SetCookie(writer, &http.Cookie{Name: "intercom-session", Value: "x", Path: "/"})
		writer.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(writer, `<script src="https://js.stripe.com/v3/"></script>`)
	}))
	defer server.Close()

	probe := NewHTTPProbe(HTTPOptions{Timeout: time.Second})
	defer probe.CloseIdleConnections()
	result, signals := probe.Probe(context.Background(), strings.TrimPrefix(server.URL, "http://"))
	if result.StatusCode != 200 || result.Error != "" {
		t.Fatalf("result = %#v", result)
	}
	assertProbeSignal(t, signals, model.ChannelHeader, "cf-ray", "")
	assertProbeSignal(t, signals, model.ChannelCookie, "intercom-session", "")
	assertProbeSignal(t, signals, model.ChannelScript, "", "js.stripe.com/v3")
}

func TestHTTPProbeUsesOnlyFinalResponseHeaders(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/" {
			writer.Header().Set("CF-Ray", "redirect-provider")
			http.Redirect(writer, request, "/home", http.StatusFound)
			return
		}
		writer.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(writer, `<html>final</html>`)
	}))
	defer server.Close()

	probe := NewHTTPProbe(HTTPOptions{Timeout: time.Second})
	defer probe.CloseIdleConnections()
	result, signals := probe.Probe(context.Background(), strings.TrimPrefix(server.URL, "http://"))
	if result.Redirects != 1 {
		t.Fatalf("redirects = %d, want 1", result.Redirects)
	}
	for _, signal := range signals {
		if signal.Channel == model.ChannelHeader && signal.Name == "cf-ray" {
			t.Fatalf("redirect header leaked into signals: %#v", signal)
		}
	}
}

func TestHTTPProbeSuppressesChallengeBody(t *testing.T) {
	t.Parallel()
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return response(request, 403, http.Header{
			"Cf-Ray":       {"abc"},
			"Content-Type": {"text/html"},
		}, `<html>Just a moment...<script src="https://js.stripe.com/v3/"></script></html>`), nil
	})
	probe := NewHTTPProbe(HTTPOptions{Timeout: time.Second, Transport: transport})
	result, signals := probe.Probe(context.Background(), "example.com")
	if !result.Blocked || !result.Challenge {
		t.Fatalf("result = %#v", result)
	}
	assertProbeSignal(t, signals, model.ChannelHeader, "cf-ray", "")
	for _, signal := range signals {
		if signal.Channel == model.ChannelScript || signal.Channel == model.ChannelHTML {
			t.Fatalf("challenge body leaked into signals: %#v", signal)
		}
	}
}

func TestHTTPProbePlain403IsDeniedNotChallenge(t *testing.T) {
	t.Parallel()
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return response(request, 403, http.Header{"Content-Type": {"text/plain"}}, "denied"), nil
	})
	probe := NewHTTPProbe(HTTPOptions{Timeout: time.Second, Transport: transport})
	result, _ := probe.Probe(context.Background(), "example.com")
	if !result.Blocked || result.Challenge || !strings.Contains(result.BlockReason, "403") {
		t.Fatalf("result = %#v", result)
	}
}

func TestHTTPProbeFallsBackOnlyAfterTransportFailure(t *testing.T) {
	t.Parallel()
	var mutex sync.Mutex
	var schemes []string
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		mutex.Lock()
		schemes = append(schemes, request.URL.Scheme)
		mutex.Unlock()
		if request.URL.Scheme == "https" {
			return nil, &temporaryNetworkError{message: "TLS transport failed"}
		}
		return response(request, 200, http.Header{"Content-Type": {"text/html"}}, "<html>ok</html>"), nil
	})
	probe := NewHTTPProbe(HTTPOptions{Timeout: time.Second, Transport: transport})
	result, _ := probe.Probe(context.Background(), "example.com")
	if result.FinalURL != "http://example.com" || strings.Join(schemes, ",") != "https,http" {
		t.Fatalf("result=%#v schemes=%v", result, schemes)
	}
}

func TestHTTPProbeDoesNotFallbackOnStatus(t *testing.T) {
	t.Parallel()
	requests := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		return response(request, 500, http.Header{"Content-Type": {"text/html"}}, "<html>error</html>"), nil
	})
	probe := NewHTTPProbe(HTTPOptions{Timeout: time.Second, Transport: transport})
	result, _ := probe.Probe(context.Background(), "example.com")
	if result.StatusCode != 500 || requests != 1 {
		t.Fatalf("result=%#v requests=%d", result, requests)
	}
}

func TestHTTPProbeBoundsBodyAndRejectsBinaryParsing(t *testing.T) {
	t.Parallel()
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return response(request, 200, http.Header{"Content-Type": {"application/octet-stream"}}, strings.Repeat("x", 101)), nil
	})
	probe := NewHTTPProbe(HTTPOptions{Timeout: time.Second, MaxBodyBytes: 100, Transport: transport})
	result, signals := probe.Probe(context.Background(), "example.com")
	if !result.BodyTruncated || result.BodyBytes != 100 {
		t.Fatalf("result = %#v", result)
	}
	for _, signal := range signals {
		if signal.Channel == model.ChannelHTML {
			t.Fatal("binary response was parsed as HTML")
		}
	}
}

func assertProbeSignal(t *testing.T, signals []model.Signal, channel model.Channel, name, valueContains string) {
	t.Helper()
	for _, signal := range signals {
		if signal.Channel == channel && (name == "" || signal.Name == name) && strings.Contains(signal.Value, valueContains) {
			return
		}
	}
	t.Fatalf("missing channel=%s name=%q value containing %q", channel, name, valueContains)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func response(request *http.Request, status int, headers http.Header, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     headers,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
}

type temporaryNetworkError struct {
	message string
}

func (err *temporaryNetworkError) Error() string   { return err.message }
func (err *temporaryNetworkError) Timeout() bool   { return false }
func (err *temporaryNetworkError) Temporary() bool { return true }

var _ net.Error = (*temporaryNetworkError)(nil)
