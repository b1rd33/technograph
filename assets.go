// Package technograph exposes the immutable assets bundled with the CLI.
package technograph

import _ "embed"

// defaultFingerprints contains the assignment fingerprint database.
//
//go:embed fingerprints.json
var defaultFingerprints []byte

// DefaultFingerprints returns an independent copy of the bundled fingerprint
// database so callers cannot mutate the embedded source.
func DefaultFingerprints() []byte {
	return append([]byte(nil), defaultFingerprints...)
}
