package mcpserver

import (
	"context"
	"fmt"

	"github.com/b1rd33/technograph/internal/agentapi"
	"github.com/b1rd33/technograph/internal/app"
	"github.com/b1rd33/technograph/internal/buildinfo"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/sync/semaphore"
)

const maxConcurrentDomains = 20

type Server struct {
	mcp         *mcp.Server
	runner      agentapi.Runner
	service     *app.Service
	domainSlots *semaphore.Weighted
}

type ScanDomainInput struct {
	Domain    string `json:"domain" jsonschema:"bare public company domain without a scheme or path"`
	RequestID string `json:"request_id,omitempty" jsonschema:"optional caller correlation identifier"`
}

type ScanDomainsInput struct {
	Domains   []string `json:"domains" jsonschema:"one to twenty bare public company domains"`
	RequestID string   `json:"request_id,omitempty" jsonschema:"optional caller correlation identifier"`
}

type ValidateDomainInput struct {
	Domain string `json:"domain" jsonschema:"bare company domain to validate without network access"`
}

type EmptyInput struct{}

// New registers the deliberately small read-only tool surface.
func New(service *app.Service) *Server {
	server := &Server{
		service:     service,
		runner:      agentapi.Runner{Service: service, MaxDomains: agentapi.DefaultMaxDomains},
		domainSlots: semaphore.NewWeighted(maxConcurrentDomains),
	}
	server.mcp = mcp.NewServer(&mcp.Implementation{
		Name: "technograph", Version: buildinfo.Version,
	}, &mcp.ServerOptions{
		Instructions: "Detect technologies from public HTTP and DNS evidence. Inputs must be bare public domains. Results are observations and may be partial when sites block automated HTTP requests.",
	})

	mcp.AddTool(server.mcp, &mcp.Tool{
		Name: "scan_domain", Description: "Scan one public domain and return detected technologies, evidence, typed status, and diagnostics.",
	}, server.scanDomain)
	mcp.AddTool(server.mcp, &mcp.Tool{
		Name: "scan_domains", Description: "Scan up to 20 public domains concurrently and return ordered structured results.",
	}, server.scanDomains)
	mcp.AddTool(server.mcp, &mcp.Tool{
		Name: "validate_domain", Description: "Validate and normalize one bare domain without making any network request.",
	}, server.validateDomain)
	mcp.AddTool(server.mcp, &mcp.Tool{
		Name: "list_fingerprints", Description: "List the embedded technology fingerprints used by this server.",
	}, server.listFingerprints)
	return server
}

// Run serves MCP over stdin/stdout until the client disconnects.
func (server *Server) Run(ctx context.Context) error {
	return server.mcp.Run(ctx, &mcp.StdioTransport{})
}

// MCP exposes the underlying server for protocol-level tests.
func (server *Server) MCP() *mcp.Server {
	return server.mcp
}

func (server *Server) scanDomain(ctx context.Context, _ *mcp.CallToolRequest, input ScanDomainInput) (*mcp.CallToolResult, agentapi.Report, error) {
	return server.scan(ctx, input.RequestID, []string{input.Domain})
}

func (server *Server) scanDomains(ctx context.Context, _ *mcp.CallToolRequest, input ScanDomainsInput) (*mcp.CallToolResult, agentapi.Report, error) {
	return server.scan(ctx, input.RequestID, input.Domains)
}

func (server *Server) scan(ctx context.Context, requestID string, domains []string) (*mcp.CallToolResult, agentapi.Report, error) {
	if len(domains) == 0 || len(domains) > agentapi.DefaultMaxDomains {
		return nil, agentapi.Report{}, fmt.Errorf("domains must contain between 1 and %d entries", agentapi.DefaultMaxDomains)
	}
	if err := server.acquire(ctx, len(domains)); err != nil {
		return nil, agentapi.Report{}, err
	}
	defer server.release(len(domains))
	report, err := server.runner.Scan(ctx, requestID, domains)
	return nil, report, err
}

func (server *Server) validateDomain(_ context.Context, _ *mcp.CallToolRequest, input ValidateDomainInput) (*mcp.CallToolResult, agentapi.DomainResult, error) {
	results, err := server.runner.Validate([]string{input.Domain})
	if err != nil {
		return nil, agentapi.DomainResult{}, err
	}
	return nil, results[0], nil
}

func (server *Server) listFingerprints(context.Context, *mcp.CallToolRequest, EmptyInput) (*mcp.CallToolResult, agentapi.FingerprintInventory, error) {
	fingerprints := server.service.Fingerprints()
	return nil, agentapi.FingerprintInventory{
		SchemaVersion: agentapi.SchemaVersion, Count: len(fingerprints), Fingerprints: fingerprints,
	}, nil
}

func (server *Server) acquire(ctx context.Context, count int) error {
	return server.domainSlots.Acquire(ctx, int64(count))
}

func (server *Server) release(count int) {
	server.domainSlots.Release(int64(count))
}
