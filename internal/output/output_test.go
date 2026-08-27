package output

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/b1rd33/technograph/internal/model"
)

func TestRequiredJSONStableAndEmptyArray(t *testing.T) {
	results := []model.ScanResult{
		{Domain: model.Domain{Hostname: "b.example"}, Technologies: []string{"Stripe"}},
		{Domain: model.Domain{Hostname: "a.example"}},
	}
	want := "{\n  \"b.example\": [\"Stripe\"],\n  \"a.example\": []\n}\n"
	first, err := RequiredJSON(results)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := RequiredJSON(results)
	if string(first) != want || string(second) != want {
		t.Fatalf("unexpected JSON:\n%s", first)
	}
}

func TestWriteAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "output.json")
	if err := WriteAtomic(path, []byte("ok")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "ok" {
		t.Fatalf("read: %q, %v", data, err)
	}
}
