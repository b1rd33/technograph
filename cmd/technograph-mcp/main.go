// Command technograph-mcp serves the scanner as a local stdio MCP server.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	technograph "github.com/b1rd33/technograph"
	"github.com/b1rd33/technograph/internal/app"
	"github.com/b1rd33/technograph/internal/buildinfo"
	"github.com/b1rd33/technograph/internal/mcpserver"
)

func main() {
	if handled, code := handleMetaCommand(os.Args[1:], os.Stdout, os.Stderr); handled {
		os.Exit(code)
	}
	historyRoot, err := parseServerArgs(os.Args[1:], os.Stderr)
	if err != nil {
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	service, _, err := app.New(app.Options{
		FingerprintData: technograph.DefaultFingerprints(), StrictFingerprints: true,
		Concurrency: 10, HTTPTimeout: 8 * time.Second, DNSTimeout: 3 * time.Second,
		DomainTimeout: 9 * time.Second, SafeNetwork: true, Logger: logger,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "technograph-mcp: %v\n", err)
		os.Exit(1)
	}
	defer service.Close()
	if err := mcpserver.NewWithOptions(service, mcpserver.Options{HistoryRoot: historyRoot}).Run(ctx); err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "technograph-mcp: %v\n", err)
		os.Exit(1)
	}
}

func handleMetaCommand(args []string, stdout, stderr io.Writer) (bool, int) {
	if len(args) == 0 {
		return false, 0
	}
	if len(args) == 1 {
		switch args[0] {
		case "--version", "-version":
			fmt.Fprintln(stdout, buildinfo.String())
			return true, 0
		case "--help", "-h":
			fmt.Fprintln(stdout, `Technograph MCP exposes the evidence-based scanner to MCP-compatible AI
clients as a local stdio server.

Usage: technograph-mcp [--history PATH]
       technograph-mcp --version

Tools:
  scan_domain       Scan one public domain with evidence and diagnostics
  scan_domains      Scan up to 20 public domains concurrently
  explain_domain    Scan and group every claim with matching evidence
  validate_domain   Validate one domain without network access
  list_fingerprints List the embedded detection rules

Optional history tools (enabled only with --history PATH):
  watch_domain      Scan, compare, and store an immutable observation
  domain_history    Read newest local observations without network access

Example client configuration:
  {
    "mcpServers": {
      "technograph": {
        "command": "technograph-mcp",
        "args": ["--history", "/absolute/path/to/history"]
      }
    }
  }

The server rejects private and reserved network targets, uses embedded
fingerprints only, and writes MCP protocol messages to stdout.`)
			return true, 0
		}
	}
	if args[0] == "--history" || strings.HasPrefix(args[0], "--history=") {
		return false, 0
	}
	fmt.Fprintln(stderr, "Usage: technograph-mcp [--history PATH] [--version]")
	return true, 2
}

func parseServerArgs(args []string, stderr io.Writer) (string, error) {
	flags := flag.NewFlagSet("technograph-mcp", flag.ContinueOnError)
	flags.SetOutput(stderr)
	historyRoot := flags.String("history", "", "fixed local immutable history directory")
	if err := flags.Parse(args); err != nil {
		return "", err
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "Usage: technograph-mcp [--history PATH]")
		return "", fmt.Errorf("unexpected positional arguments")
	}
	return *historyRoot, nil
}
