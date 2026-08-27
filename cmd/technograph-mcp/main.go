// Command technograph-mcp serves the scanner as a local stdio MCP server.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
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
	if err := mcpserver.New(service).Run(ctx); err != nil && ctx.Err() == nil {
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
			fmt.Fprintln(stdout, "Usage: technograph-mcp [--version]")
			fmt.Fprintln(stdout, "\nRuns the read-only Technograph MCP server over stdin/stdout.")
			return true, 0
		}
	}
	fmt.Fprintln(stderr, "Usage: technograph-mcp [--version]")
	return true, 2
}
