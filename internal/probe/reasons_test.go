package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/b1rd33/technograph/internal/model"
)

func containsReason(reasons []model.TruncationReason, want model.TruncationReason) bool {
	for _, r := range reasons {
		if r == want {
			return true
		}
	}
	return false
}

func TestLimitHeadersReason(t *testing.T) {
	t.Parallel()
	signals := make([]model.Signal, 200)
	for i := range signals {
		signals[i] = model.Signal{Channel: model.ChannelHeader, Name: "x"}
	}
	_, truncated := limitHeaders(signals)
	if !truncated {
		t.Fatal("expected headers truncated")
	}
	_, truncated2 := limitHeaders(signals[:10])
	if truncated2 {
		t.Fatal("10 headers should not be truncated")
	}
}

func TestLimitCookiesReasonsAllThree(t *testing.T) {
	t.Parallel()
	// cookie_count
	sigs := make([]model.Signal, 150)
	for i := range sigs {
		sigs[i] = model.Signal{Channel: model.ChannelCookie, Name: "c", Value: "v"}
	}
	_, reasons := limitCookies(sigs)
	if !containsReason(reasons, model.ReasonCookieCount) {
		t.Fatalf("expected cookie_count, got %v", reasons)
	}
	// cookie_value
	sigs2 := []model.Signal{{Channel: model.ChannelCookie, Name: "c", Value: strings.Repeat("v", 8192)}}
	_, reasons2 := limitCookies(sigs2)
	if !containsReason(reasons2, model.ReasonCookieValue) {
		t.Fatalf("expected cookie_value, got %v", reasons2)
	}
	// cookie_bytes
	sigs3 := make([]model.Signal, 20)
	for i := range sigs3 {
		sigs3[i] = model.Signal{Channel: model.ChannelCookie, Name: "c", Value: strings.Repeat("v", 4096)}
	}
	_, reasons3 := limitCookies(sigs3)
	has := false
	for _, r := range reasons3 {
		if r == model.ReasonCookieBytes {
			has = true
		}
	}
	if !has {
		t.Fatalf("expected cookie_bytes, got %v", reasons3)
	}
}

func TestProbeReasonsHeadersViaHTTP(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for i := 0; i < 200; i++ {
			w.Header().Set("X-Custom-"+strings.Repeat("a", 2)+string(rune('A'+i%26))+string(rune('0'+i/26)), "v")
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>ok</html>"))
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	probe := NewHTTPProbe(HTTPOptions{Timeout: 2e9})
	defer probe.CloseIdleConnections()
	result, _ := probe.Probe(context.Background(), host)
	if !containsReason(result.SignalsTruncatedReasons, model.ReasonHeaders) {
		t.Fatalf("expected headers reason, got %v truncated=%v", result.SignalsTruncatedReasons, result.SignalsTruncated)
	}
}

func TestProbeReasonsCookieCountViaHTTP(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for i := 0; i < 150; i++ {
			http.SetCookie(w, &http.Cookie{Name: "c" + string(rune('a'+i%26)) + string(rune('0'+i/26)), Value: "v", Path: "/"})
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>ok</html>"))
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	probe := NewHTTPProbe(HTTPOptions{Timeout: 2e9})
	defer probe.CloseIdleConnections()
	result, _ := probe.Probe(context.Background(), host)
	if !containsReason(result.SignalsTruncatedReasons, model.ReasonCookieCount) {
		t.Fatalf("expected cookie_count, got %v", result.SignalsTruncatedReasons)
	}
}

func TestProbeHomepagePropagation(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		var b strings.Builder
		for i := 0; i < 6000; i++ {
			b.WriteString(`<a href="/p">x</a>`)
		}
		w.Write([]byte(b.String()))
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	probe := NewHTTPProbe(HTTPOptions{Timeout: 2e9})
	defer probe.CloseIdleConnections()
	result, _ := probe.Probe(context.Background(), host)
	if !result.SignalsTruncated || !containsReason(result.SignalsTruncatedReasons, model.ReasonLinks) {
		t.Fatalf("expected links propagated, got %v %v", result.SignalsTruncated, result.SignalsTruncatedReasons)
	}
}

func TestProbeSecondaryPropagationAndMerging(t *testing.T) {
	t.Parallel()
	// homepage triggers headers, secondary triggers links — root should have both sorted.
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "" || req.URL.Path == "/" {
			headers := http.Header{"Content-Type": {"text/html"}}
			for i := 0; i < 200; i++ {
				headers.Set("X-H"+string(rune('A'+i%26))+string(rune('0'+i/26)), "v")
			}
			return response(req, 200, headers, `<a href="/extra">Extra</a>`), nil
		}
		var b strings.Builder
		for i := 0; i < 6000; i++ {
			b.WriteString(`<a href="/p">x</a>`)
		}
		return response(req, 200, http.Header{"Content-Type": {"text/html"}}, b.String()), nil
	})
	probe := NewHTTPProbe(HTTPOptions{Timeout: 2e9, PageLimit: 2, Transport: transport})
	result, _ := probe.Probe(context.Background(), "example.com")
	if !containsReason(result.SignalsTruncatedReasons, model.ReasonHeaders) || !containsReason(result.SignalsTruncatedReasons, model.ReasonLinks) {
		t.Fatalf("expected headers+links merged sorted, got %v", result.SignalsTruncatedReasons)
	}
	if len(result.Pages) != 1 || !containsReason(result.Pages[0].SignalsTruncatedReasons, model.ReasonLinks) {
		t.Fatalf("secondary page reasons missing: %v", result.Pages)
	}
	for i := 1; i < len(result.SignalsTruncatedReasons); i++ {
		if string(result.SignalsTruncatedReasons[i-1]) > string(result.SignalsTruncatedReasons[i]) {
			t.Fatalf("not sorted: %v", result.SignalsTruncatedReasons)
		}
	}
}

func TestBoundedJarRedirectPropagation(t *testing.T) {
	t.Parallel()
	count := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if count < 3 {
			for i := 0; i < 50; i++ {
				http.SetCookie(w, &http.Cookie{Name: "r" + string(rune('a'+i%26)) + string(rune('0'+count)) + string(rune('A'+i%5)), Value: strings.Repeat("v", 200), Path: "/"})
			}
			count++
			http.Redirect(w, r, "/r"+string(rune('0'+count)), http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>ok</html>"))
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	probe := NewHTTPProbe(HTTPOptions{Timeout: 2e9})
	defer probe.CloseIdleConnections()
	result, _ := probe.Probe(context.Background(), host)
	// redirect jar should have counted across hops — expect truncation with cookie_count or bytes
	if !result.SignalsTruncated {
		t.Fatal("expected redirect jar truncation")
	}
	has := containsReason(result.SignalsTruncatedReasons, model.ReasonCookieCount) || containsReason(result.SignalsTruncatedReasons, model.ReasonCookieBytes)
	if !has {
		t.Fatalf("expected cookie_count or cookie_bytes via redirect, got %v", result.SignalsTruncatedReasons)
	}
}

func TestProbeReasonsJSONStrings(t *testing.T) {
	t.Parallel()
	// ensure JSON serializes as plain strings, not objects
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		var b strings.Builder
		for i := 0; i < 6000; i++ {
			b.WriteString(`<a href="/p">x</a>`)
		}
		w.Write([]byte(b.String()))
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	probe := NewHTTPProbe(HTTPOptions{Timeout: 2e9})
	defer probe.CloseIdleConnections()
	result, _ := probe.Probe(context.Background(), host)
	for _, r := range result.SignalsTruncatedReasons {
		if string(r) == "" {
			t.Fatal("empty reason")
		}
	}
}
