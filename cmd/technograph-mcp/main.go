// Command technograph-mcp serves the scanner as a local stdio MCP server.
package main

import (
	"context"
	"fmt"
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
	if len(os.Args) == 2 && (os.Args[1] == "--version" || os.Args[1] == "-version") {
		fmt.Fprintln(os.Stdout, buildinfo.String())
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "Usage: technograph-mcp [--version]")
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
	if err := mcpserver.New(service).Run(ctx); err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "technograph-mcp: %v\n", err)
		os.Exit(1)
	}
}
