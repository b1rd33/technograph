// Package output writes deterministic scan artifacts atomically.
package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/b1rd33/technograph/internal/model"
)

// RequiredJSON returns the exact assignment shape while preserving input order.
func RequiredJSON(results []model.ScanResult) ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteString("{\n")
	for index, result := range results {
		key, err := json.Marshal(result.Domain.Hostname)
		if err != nil {
			return nil, err
		}
		technologies := result.Technologies
		if technologies == nil {
			technologies = []string{}
		}
		value, err := json.Marshal(technologies)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&buffer, "  %s: %s", key, value)
		if index+1 < len(results) {
			buffer.WriteByte(',')
		}
		buffer.WriteByte('\n')
	}
	buffer.WriteString("}\n")
	return buffer.Bytes(), nil
}

func ReportJSON(results []model.ScanResult) ([]byte, error) {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// WriteAtomic replaces path only after the complete artifact is on disk.
func WriteAtomic(path string, data []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".technograph-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err = temporary.Write(data); err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write temporary output: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace output: %w", err)
	}
	return nil
}
