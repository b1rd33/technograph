// Command technograph is the entry point for the technographic detection CLI.
package main

import (
	"context"
	"os"

	technograph "github.com/b1rd33/technograph"
	"github.com/b1rd33/technograph/internal/cli"
)

func main() {
	os.Exit(cli.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, technograph.DefaultFingerprints()))
}
