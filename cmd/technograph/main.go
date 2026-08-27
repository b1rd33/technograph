// Command technograph is the entry point for the technographic detection CLI.
package main

import (
	"context"
	"os"

	technograph "github.com/christiannikolov/technograph"
	"github.com/christiannikolov/technograph/internal/cli"
)

func main() {
	os.Exit(cli.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, technograph.DefaultFingerprints()))
}
