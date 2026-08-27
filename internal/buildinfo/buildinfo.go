// Package buildinfo exposes release metadata injected by GoReleaser.
package buildinfo

import "fmt"

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// String returns a stable, human-readable version line.
func String() string {
	return fmt.Sprintf("technograph %s (commit %s, built %s)", Version, Commit, Date)
}
