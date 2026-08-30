package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/b1rd33/technograph/internal/model"
)

func TestLimitHeadersTruncatesAt128(t *testing.T) {
	t.Parallel()
	signals := make([]model.Signal, 0)
	for i := 0; i < 200; i++ {
		signals = append(signals, model.Signal{Channel: model.ChannelHeader, Name: "x-header", Value: "v"})
	}
	limited, _ := limitHeaders(signals)
	if len(limited) != 128 {
		t.Fatalf("headers = %d, want 128", len(limited))
	}
	small := make([]model.Signal, 10)
	for i := range small {
		small[i] = model.Signal{Channel: model.ChannelHeader, Name: "x", Value: "v"}
	}
	smallLimited, _ := limitHeaders(small)
	if len(smallLimited) != 10 {
		t.Fatalf("small headers should not be truncated")
	}
}

func TestLimitCookiesBoundsCountAndBytes(t *testing.T) {
	t.Parallel()
	signals := make([]model.Signal, 0)
	for i := 0; i < 200; i++ {
		signals = append(signals, model.Signal{Channel: model.ChannelCookie, Name: "c", Value: strings.Repeat("v", 100)})
	}
	limited, _ := limitCookies(signals)
	if len(limited) != 100 {
		t.Fatalf("cookies = %d, want 100", len(limited))
	}
}

func TestLimitCookiesTruncatesValueAt4096(t *testing.T) {
	t.Parallel()
	signals := []model.Signal{{Channel: model.ChannelCookie, Name: "c", Value: strings.Repeat("v", 8192)}}
	limited, _ := limitCookies(signals)
	if len(limited[0].Value) != maxCookieValueLen {
		t.Fatalf("cookie value len = %d, want %d", len(limited[0].Value), maxCookieValueLen)
	}
}

func TestOversizedCookieValueVisibleAsTruncated(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "big", Value: strings.Repeat("v", 8192), Path: "/"})
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>ok</html>"))
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	probe := NewHTTPProbe(HTTPOptions{Timeout: 2 * 1e9})
	defer probe.CloseIdleConnections()
	result, _ := probe.Probe(context.Background(), host)
	if !result.SignalsTruncated {
		t.Fatal("expected SignalsTruncated=true when single cookie value exceeds 4096 and is shortened")
	}
}

func TestLimitCookiesBoundsTotalBytesAt32K(t *testing.T) {
	t.Parallel()
	signals := make([]model.Signal, 0)
	for i := 0; i < 20; i++ {
		signals = append(signals, model.Signal{Channel: model.ChannelCookie, Name: "c", Value: strings.Repeat("v", 4096)})
	}
	limited, _ := limitCookies(signals)
	total := 0
	for _, s := range limited {
		total += len(s.Value)
	}
	if total > maxCookieBytes {
		t.Fatalf("total cookie bytes = %d, want <= %d", total, maxCookieBytes)
	}
	if len(limited) != 8 {
		t.Fatalf("cookies at 4K each = %d, want 8 (32K cap)", len(limited))
	}
}

func TestLimitCookiesSmallBatchUnaffected(t *testing.T) {
	t.Parallel()
	signals := []model.Signal{
		{Channel: model.ChannelCookie, Name: "intercom-session", Value: "x"},
		{Channel: model.ChannelCookie, Name: "__cf_bm", Value: "y"},
	}
	limited, _ := limitCookies(signals)
	if len(limited) != 2 {
		t.Fatalf("normal cookies truncated: %d", len(limited))
	}
}

func TestMaxResponseHeaderBytesIsSet(t *testing.T) {
	t.Parallel()
	probe := NewHTTPProbe(HTTPOptions{})
	transport, ok := probe.transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", probe.transport)
	}
	if transport.MaxResponseHeaderBytes != int64(maxResponseHeaderKB) {
		t.Fatalf("MaxResponseHeaderBytes = %d, want %d", transport.MaxResponseHeaderBytes, maxResponseHeaderKB)
	}
}

func TestProbeCookieBudgetsViaHTTPCookies(t *testing.T) {
	t.Parallel()
	signals := make([]model.Signal, 0)
	for i := 0; i < 150; i++ {
		signals = append(signals, model.Signal{Channel: model.ChannelCookie, Name: "c", Value: strings.Repeat("v", 10)})
	}
	limited, _ := limitCookies(signals)
	if len(limited) != maxCookies {
		t.Fatalf("probe cookie budget = %d, want %d", len(limited), maxCookies)
	}
}

func TestProbeHeaderBudgetUnaffectedForNormalHeaders(t *testing.T) {
	t.Parallel()
	signals := []model.Signal{
		{Channel: model.ChannelHeader, Name: "cf-ray", Value: "abc"},
		{Channel: model.ChannelHeader, Name: "x-stripe-some", Value: "v"},
	}
	limited, _ := limitHeaders(signals)
	if len(limited) != 2 {
		t.Fatal("normal headers truncated unexpectedly")
	}
}

func TestBoundedJarCumulativeAcrossHosts(t *testing.T) {
	t.Parallel()
	jar := &boundedJar{jar: newJar(), maxCookies: 5, maxCookieBytes: 10 << 20}
	u1, _ := url.Parse("https://a.example/")
	u2, _ := url.Parse("https://b.example/")
	cookies1 := make([]*http.Cookie, 5)
	for i := range cookies1 {
		cookies1[i] = &http.Cookie{Name: "c" + string(rune('a'+i)), Value: "v", Path: "/"}
	}
	jar.SetCookies(u1, cookies1)
	// Second host should be blocked by cumulative count, not per-host.
	cookies2 := []*http.Cookie{{Name: "extra", Value: "v", Path: "/"}}
	jar.SetCookies(u2, cookies2)
	if got := len(jar.Cookies(u2)); got != 0 {
		t.Fatalf("cumulative: second host cookies %d, want 0 (budget exhausted)", got)
	}
	if got := len(jar.Cookies(u1)); got != 5 {
		t.Fatalf("first host cookies %d, want 5", got)
	}
}

func TestProbeRedirectCookieBudgetReal(t *testing.T) {
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
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	probe := NewHTTPProbe(HTTPOptions{Timeout: 2 * 1e9})
	defer probe.CloseIdleConnections()
	result, signals := probe.Probe(context.Background(), host)
	if result.Error != "" {
		t.Fatalf("probe error: %s", result.Error)
	}
	cookies := 0
	total := 0
	for _, s := range signals {
		if s.Channel == model.ChannelCookie {
			cookies++
			total += len(s.Value)
		}
	}
	if cookies > maxCookies {
		t.Fatalf("redirect cookies %d > %d", cookies, maxCookies)
	}
	if total > maxCookieBytes {
		t.Fatalf("redirect cookie bytes %d > %d", total, maxCookieBytes)
	}
}

func TestHTMLSignalsTruncatedEndToEnd(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		var b strings.Builder
		b.WriteString("<html><body>")
		for i := 0; i < 6000; i++ {
			b.WriteString(`<a href="/p">x</a>`)
		}
		w.Write([]byte(b.String()))
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	probe := NewHTTPProbe(HTTPOptions{Timeout: 2 * 1e9})
	defer probe.CloseIdleConnections()
	result, _ := probe.Probe(context.Background(), host)
	if !result.SignalsTruncated {
		t.Fatal("expected SignalsTruncated=true for 6000-link HTML")
	}
}

func TestWindowNamesTruncatedEndToEnd(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString("<script>")
	for i := 0; i < 600; i++ {
		b.WriteString("window.var")
		n := i
		numStr := ""
		for n > 0 || numStr == "" {
			numStr = string(rune('0'+n%10)) + numStr
			n /= 10
			if numStr == "" {
				numStr = "0"
				break
			}
			if n == 0 {
				break
			}
		}
		b.WriteString(numStr)
		b.WriteString(" = 1; ")
	}
	b.WriteString("</script>")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(b.String()))
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	probe := NewHTTPProbe(HTTPOptions{Timeout: 2 * 1e9})
	defer probe.CloseIdleConnections()
	result, _ := probe.Probe(context.Background(), host)
	if !result.SignalsTruncated {
		t.Fatal("expected SignalsTruncated for 600 window names")
	}
}

func TestCookieDroppedIsSignaled(t *testing.T) {
	t.Parallel()
	count := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 150; i++ {
			http.SetCookie(w, &http.Cookie{Name: "c" + string(rune('a'+i%26)) + string(rune('0'+i/26)), Value: "v", Path: "/"})
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>ok</html>"))
		_ = count
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	probe := NewHTTPProbe(HTTPOptions{Timeout: 2 * 1e9})
	defer probe.CloseIdleConnections()
	result, _ := probe.Probe(context.Background(), host)
	if !result.SignalsTruncated {
		t.Fatal("expected SignalsTruncated when 150 cookies exceed 100 limit")
	}
}

func TestSecondaryPageTruncatedPropagates(t *testing.T) {
	t.Parallel()
	var requested []string
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requested = append(requested, req.URL.String())
		if req.URL.Path == "" || req.URL.Path == "/" {
			return response(req, 200, http.Header{"Content-Type": {"text/html"}}, `<a href="/extra">Extra</a>`), nil
		}
		var b strings.Builder
		b.WriteString("<html><body>")
		for i := 0; i < 6000; i++ {
			b.WriteString(`<a href="/p">x</a>`)
		}
		b.WriteString("</body></html>")
		return response(req, 200, http.Header{"Content-Type": {"text/html"}}, b.String()), nil
	})
	probe := NewHTTPProbe(HTTPOptions{Timeout: 2 * 1e9, PageLimit: 2, Transport: transport})
	result, _ := probe.Probe(context.Background(), "example.com")
	if len(requested) != 2 {
		t.Fatalf("requests = %v, want 2", requested)
	}
	if len(result.Pages) != 1 {
		t.Fatalf("pages = %v", result.Pages)
	}
	if !result.Pages[0].SignalsTruncated {
		t.Fatal("expected secondary page SignalsTruncated=true")
	}
	if !result.SignalsTruncated {
		t.Fatal("expected root SignalsTruncated=true when secondary truncates")
	}
}
