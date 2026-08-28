package mcpserver

import (
	"context"
	"testing"
	"time"

	"github.com/b1rd33/technograph/internal/app"
	"github.com/b1rd33/technograph/internal/model"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type stubHTTP struct{}

func (stubHTTP) Probe(context.Context, string) (model.HTTPResult, []model.Signal) {
	return model.HTTPResult{StatusCode: 200}, []model.Signal{{Channel: model.ChannelHeader, Name: "cf-ray"}}
}

func TestGlobalLimiterAcquiresBatchCapacityAtomically(t *testing.T) {
	service, _, err := app.New(app.Options{
		FingerprintData:    []byte(`{"schema_version":1,"technologies":{"Cloudflare":{"header":"cf-ray"}}}`),
		StrictFingerprints: true, HTTP: stubHTTP{}, DNS: stubDNS{},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	server := New(service)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.acquire(ctx, 15); err != nil {
		t.Fatal(err)
	}
	acquired := make(chan error, 1)
	go func() { acquired <- server.acquire(ctx, 15) }()
	select {
	case err := <-acquired:
		t.Fatalf("second batch acquired before capacity was released: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	server.release(15)
	select {
	case err := <-acquired:
		if err != nil {
			t.Fatal(err)
		}
		server.release(15)
	case <-ctx.Done():
		t.Fatal("second atomic acquisition did not complete")
	}
}

type stubDNS struct{}

func (stubDNS) Probe(context.Context, string) (model.DNSResult, []model.Signal) {
	return model.DNSResult{Status: map[string]string{"mx": "nodata", "txt": "nodata", "cname": "nodata"}}, nil
}

func TestServerToolsThroughMCPClient(t *testing.T) {
	service, _, err := app.New(app.Options{
		FingerprintData:    []byte(`{"schema_version":1,"technologies":{"Cloudflare":{"header":"cf-ray"}}}`),
		StrictFingerprints: true, HTTP: stubHTTP{}, DNS: stubDNS{},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	server := New(service)

	ctx := context.Background()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.MCP().Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()

	tools, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 5 {
		t.Fatalf("tools = %d, want 5", len(tools.Tools))
	}
	result, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "scan_domain", Arguments: map[string]any{"domain": "example.com", "request_id": "test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError || result.StructuredContent == nil {
		t.Fatalf("result = %#v", result)
	}
	explanation, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "explain_domain", Arguments: map[string]any{"domain": "example.com", "request_id": "explain"},
	})
	if err != nil || explanation.IsError || explanation.StructuredContent == nil {
		t.Fatalf("explanation=%#v error=%v", explanation, err)
	}
}

func TestHistoryToolsAreOptInAndRoundTripThroughMCP(t *testing.T) {
	service, _, err := app.New(app.Options{
		FingerprintData:    []byte(`{"schema_version":1,"technologies":{"Cloudflare":{"header":"cf-ray"}}}`),
		StrictFingerprints: true, HTTP: stubHTTP{}, DNS: stubDNS{},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	server := NewWithOptions(service, Options{HistoryRoot: t.TempDir()})

	ctx := context.Background()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.MCP().Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "history-client", Version: "1"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()

	tools, err := clientSession.ListTools(ctx, nil)
	if err != nil || len(tools.Tools) != 7 {
		t.Fatalf("tools=%#v error=%v", tools, err)
	}
	for _, requestID := range []string{"first", "second"} {
		result, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
			Name: "watch_domain", Arguments: map[string]any{"domain": "example.com", "request_id": requestID},
		})
		if err != nil || result.IsError || result.StructuredContent == nil {
			t.Fatalf("watch=%#v error=%v", result, err)
		}
	}
	result, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "domain_history", Arguments: map[string]any{"domain": "example.com", "limit": 2},
	})
	if err != nil || result.IsError || result.StructuredContent == nil {
		t.Fatalf("history=%#v error=%v", result, err)
	}
}
