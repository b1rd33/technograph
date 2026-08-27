// Command technograph is the entry point for the technographic detection CLI.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	technograph "github.com/b1rd33/technograph"
	"github.com/b1rd33/technograph/internal/agentcli"
	"github.com/b1rd33/technograph/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	args := os.Args[1:]
	if len(args) > 0 && isStructuredCommand(args[0]) {
		os.Exit(agentcli.Run(ctx, args, os.Stdin, os.Stdout, os.Stderr, technograph.DefaultFingerprints()))
	}
	os.Exit(cli.Run(ctx, args, os.Stdout, os.Stderr, technograph.DefaultFingerprints()))
}

func isStructuredCommand(argument string) bool {
	switch argument {
	case "scan", "validate", "fingerprints", "compare", "help", "-h", "--help":
		return true
	default:
		return false
	}
}
