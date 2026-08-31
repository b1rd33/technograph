package mcpserver

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/b1rd33/technograph/internal/agentapi"
	"github.com/b1rd33/technograph/internal/app"
	"github.com/b1rd33/technograph/internal/history"
	"github.com/b1rd33/technograph/internal/model"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func expectedTruncationEnum() []string {
	return []string{
		string(model.ReasonLinks),
		string(model.ReasonSignals),
		string(model.ReasonInlineScripts),
		string(model.ReasonWindowNames),
		string(model.ReasonHeaders),
		string(model.ReasonCookieCount),
		string(model.ReasonCookieBytes),
		string(model.ReasonCookieValue),
	}
}

// TestMCPOutputSchemasAdvertiseTruncationEnum exercises the real MCP server's
// tools/list path and inspects every signals_truncated_reasons field.
func TestMCPOutputSchemasAdvertiseTruncationEnum(t *testing.T) {
	t.Parallel()
	service, _, err := app.New(app.Options{
		FingerprintData:    []byte(`{"schema_version":1,"technologies":{"Cloudflare":{"header":"cf-ray"}}}`),
		StrictFingerprints: true, HTTP: stubHTTP{}, DNS: stubDNS{},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	cases := []struct {
		name    string
		history bool
	}{
		{"default", false},
		{"history-enabled", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var server *Server
			if c.history {
				server = NewWithOptions(service, Options{HistoryRoot: t.TempDir()})
			} else {
				server = New(service)
			}
			ctx := context.Background()
			serverTransport, clientTransport := mcp.NewInMemoryTransports()
			serverSession, err := server.MCP().Connect(ctx, serverTransport, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer serverSession.Close()
			client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
			clientSession, err := client.Connect(ctx, clientTransport, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer clientSession.Close()

			tools, err := clientSession.ListTools(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			expected := expectedTruncationEnum()

			toolMap := make(map[string]*mcp.Tool, len(tools.Tools))
			for _, tool := range tools.Tools {
				toolMap[tool.Name] = tool
			}

			if c.history {
				if len(tools.Tools) != 7 {
					t.Fatalf("history tools = %d, want 7", len(tools.Tools))
				}
			} else {
				if len(tools.Tools) != 5 {
					t.Fatalf("default tools = %d, want 5", len(tools.Tools))
				}
			}

			expectedCounts := map[string]int{
				"scan_domain":       2,
				"scan_domains":      2,
				"validate_domain":   2,
				"explain_domain":    0,
				"list_fingerprints": 0,
			}
			if c.history {
				expectedCounts["watch_domain"] = 2
				expectedCounts["domain_history"] = 2
			}

			for toolName, wantCount := range expectedCounts {
				tool, ok := toolMap[toolName]
				if !ok {
					t.Fatalf("tool %q not found", toolName)
				}
				found, err := findTruncationReasonsWithPath(tool.OutputSchema)
				if err != nil {
					t.Fatalf("tool %q find output truncation: %v", toolName, err)
				}
				if len(found) != wantCount {
					paths := make([]string, 0, len(found))
					for _, f := range found {
						paths = append(paths, f.Path)
					}
					t.Fatalf("tool %q signals_truncated_reasons occurrences = %d (%v), want %d", toolName, len(found), paths, wantCount)
				}
				for _, f := range found {
					assertEnumFieldWithPath(t, toolName, f, expected)
				}
				if wantCount == 2 {
					assertExpectedPaths(t, toolName, found)
				}
				inpFound, err := findTruncationReasonsWithPath(tool.InputSchema)
				if err != nil {
					t.Fatalf("tool %q find input truncation: %v", toolName, err)
				}
				if len(inpFound) != 0 {
					paths := make([]string, 0, len(inpFound))
					for _, f := range inpFound {
						paths = append(paths, f.Path)
					}
					t.Fatalf("tool %q input schema must not contain signals_truncated_reasons, found %v", toolName, paths)
				}
			}

			var firstEnum []string
			for _, tool := range tools.Tools {
				found, err := findTruncationReasonsWithPath(tool.OutputSchema)
				if err != nil {
					t.Fatalf("tool %q find for enum identity: %v", tool.Name, err)
				}
				for _, f := range found {
					enum := extractEnumFromField(f.Field)
					if firstEnum == nil {
						firstEnum = enum
					} else {
						if len(firstEnum) != len(enum) {
							t.Fatalf("enum len mismatch: %v vs %v in tool %q", firstEnum, enum, tool.Name)
						}
						for i := range firstEnum {
							if firstEnum[i] != enum[i] {
								t.Fatalf("enum order mismatch at %d: %q vs %q in tool %q (expected deterministic order)", i, firstEnum[i], enum[i], tool.Name)
							}
						}
					}
				}
			}

			if scanDomain, ok := toolMap["scan_domain"]; ok {
				raw, err := json.Marshal(scanDomain.InputSchema)
				if err != nil {
					t.Fatalf("marshal scan_domain input schema: %v", err)
				}
				var m map[string]any
				if err := json.Unmarshal(raw, &m); err != nil {
					t.Fatalf("unmarshal scan_domain input schema: %v", err)
				}
				props, ok := m["properties"].(map[string]any)
				if !ok {
					t.Fatalf("scan_domain input missing properties: %v", m)
				}
				if _, ok := props["domain"]; !ok {
					t.Fatal("scan_domain input missing domain property")
				}
				required, ok := m["required"].([]any)
				if !ok {
					t.Fatalf("scan_domain input missing required array: %v", m)
				}
				found := false
				for _, r := range required {
					s, ok := r.(string)
					if !ok {
						t.Fatalf("scan_domain input required element not string: %v", r)
					}
					if s == "domain" {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("scan_domain input required %v must contain domain", required)
				}
				for _, tool := range tools.Tools {
					occ, err := findTruncationReasonsWithPath(tool.InputSchema)
					if err != nil {
						t.Fatalf("tool %q input find: %v", tool.Name, err)
					}
					if len(occ) != 0 {
						t.Fatalf("tool %q input schema contains signals_truncated_reasons", tool.Name)
					}
				}
			}

			for _, r := range expected {
				b, err := json.Marshal(model.TruncationReason(r))
				if err != nil {
					t.Fatalf("marshal TruncationReason %q: %v", r, err)
				}
				var s string
				if err := json.Unmarshal(b, &s); err != nil {
					t.Fatalf("unmarshal TruncationReason %q: %v", r, err)
				}
				if s != r {
					t.Fatalf("TruncationReason %q JSON %q mismatch", r, s)
				}
			}
		})
	}
}

type foundField struct {
	Path  string
	Field map[string]any
}

func findTruncationReasonsWithPath(schema any) ([]foundField, error) {
	if schema == nil {
		return nil, nil
	}
	raw, err := json.Marshal(schema)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	var results []foundField
	var walk func(node any, path string) error
	walk = func(node any, path string) error {
		switch v := node.(type) {
		case map[string]any:
			if field, ok := v["signals_truncated_reasons"]; ok {
				fm, ok := field.(map[string]any)
				if !ok {
					return nil
				}
				fieldPath := path + ".signals_truncated_reasons"
				if path == "" {
					fieldPath = "signals_truncated_reasons"
				}
				fieldPath = strings.TrimPrefix(fieldPath, ".")
				results = append(results, foundField{Path: fieldPath, Field: fm})
			}
			for k, child := range v {
				childPath := k
				if path != "" {
					childPath = path + "." + k
				}
				if err := walk(child, childPath); err != nil {
					return err
				}
			}
		case []any:
			for i, child := range v {
				childPath := path + "[" + strconv.Itoa(i) + "]"
				if err := walk(child, childPath); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(m, ""); err != nil {
		return nil, err
	}
	return results, nil
}

func assertEnumFieldWithPath(t *testing.T, toolName string, found foundField, expected []string) {
	t.Helper()
	field := found.Field
	typ := field["type"]
	var types []string
	switch v := typ.(type) {
	case string:
		types = []string{v}
	case []any:
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				t.Fatalf("tool %q %q type element not string: %v", toolName, found.Path, e)
			}
			types = append(types, s)
		}
	case nil:
		t.Fatalf("tool %q %q missing type", toolName, found.Path)
	default:
		t.Fatalf("tool %q %q type unexpected %T %v", toolName, found.Path, v, v)
	}
	if len(types) != 2 {
		t.Fatalf("tool %q %q type %v, want exactly [\"null\", \"array\"]", toolName, found.Path, typ)
	}
	typeSet := make(map[string]bool, len(types))
	for _, tt := range types {
		typeSet[tt] = true
	}
	if !typeSet["null"] || !typeSet["array"] {
		t.Fatalf("tool %q %q type %v, want [\"null\", \"array\"]", toolName, found.Path, typ)
	}
	items, ok := field["items"].(map[string]any)
	if !ok || items == nil {
		t.Fatalf("tool %q %q missing items", toolName, found.Path)
	}
	if items["type"] != "string" {
		t.Fatalf("tool %q %q items.type = %v, want string", toolName, found.Path, items["type"])
	}
	rawEnum, ok := items["enum"].([]any)
	if !ok {
		t.Fatalf("tool %q %q missing items.enum", toolName, found.Path)
	}
	if len(rawEnum) != len(expected) {
		t.Fatalf("tool %q %q enum len = %d (%v), want %d (%v)", toolName, found.Path, len(rawEnum), rawEnum, len(expected), expected)
	}
	for i, e := range rawEnum {
		s, ok := e.(string)
		if !ok {
			t.Fatalf("tool %q %q enum[%d] not string: %v", toolName, found.Path, i, e)
		}
		if s != expected[i] {
			t.Fatalf("tool %q %q enum[%d] = %q, want %q (deterministic order)", toolName, found.Path, i, s, expected[i])
		}
	}
	seen := make(map[string]bool, len(rawEnum))
	for _, e := range rawEnum {
		s, ok := e.(string)
		if !ok {
			t.Fatalf("tool %q %q enum element not string: %v", toolName, found.Path, e)
		}
		if seen[s] {
			t.Fatalf("tool %q %q duplicate enum %q", toolName, found.Path, s)
		}
		seen[s] = true
	}
	if seen["unknown"] {
		t.Fatalf("tool %q %q contains unknown", toolName, found.Path)
	}
	expectedSet := make(map[string]bool, len(expected))
	for _, e := range expected {
		expectedSet[e] = true
	}
	for s := range seen {
		if !expectedSet[s] {
			t.Fatalf("tool %q %q unexpected enum %q", toolName, found.Path, s)
		}
	}
	for _, exp := range expected {
		if !seen[exp] {
			t.Fatalf("tool %q %q missing expected %q", toolName, found.Path, exp)
		}
	}
	if _, hasEnum := field["enum"]; hasEnum {
		t.Fatalf("tool %q %q enum incorrectly on array, not items", toolName, found.Path)
	}
}

func assertExpectedPaths(t *testing.T, toolName string, found []foundField) {
	t.Helper()
	paths := make([]string, 0, len(found))
	for _, f := range found {
		paths = append(paths, f.Path)
	}
	hasHomepage, hasSecondary := false, false
	for _, p := range paths {
		if strings.HasSuffix(p, ".http.properties.signals_truncated_reasons") {
			hasHomepage = true
		}
		if strings.HasSuffix(p, ".http.properties.pages.items.properties.signals_truncated_reasons") {
			hasSecondary = true
		}
	}
	if !hasHomepage {
		t.Fatalf("tool %q missing homepage path (expected suffix .http.properties.signals_truncated_reasons), found %v", toolName, paths)
	}
	if !hasSecondary {
		t.Fatalf("tool %q missing secondary-page path (expected suffix .http.properties.pages.items.properties.signals_truncated_reasons), found %v", toolName, paths)
	}
}

func extractEnumFromField(field map[string]any) []string {
	items, ok := field["items"].(map[string]any)
	if !ok {
		return nil
	}
	rawEnum, ok := items["enum"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(rawEnum))
	for _, e := range rawEnum {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func TestCustomSchemaOnlyAddsEnum(t *testing.T) {
	t.Parallel()
	t.Run("Report", func(t *testing.T) { assertCustomOnlyAddsEnum[agentapi.Report](t) })
	t.Run("DomainResult", func(t *testing.T) { assertCustomOnlyAddsEnum[agentapi.DomainResult](t) })
	t.Run("WatchReport", func(t *testing.T) { assertCustomOnlyAddsEnum[history.WatchReport](t) })
	t.Run("HistoryReport", func(t *testing.T) { assertCustomOnlyAddsEnum[history.Report](t) })
}

func assertCustomOnlyAddsEnum[T any](t *testing.T) {
	t.Helper()
	defaultSchema, err := jsonschema.For[T](nil)
	if err != nil {
		t.Fatalf("default schema: %v", err)
	}
	customSchema := mustSchemaWithTruncationEnum[T]()
	assertSchemasEqualAfterStrippingEnum(t, defaultSchema, customSchema)
}

func assertSchemasEqualAfterStrippingEnum(t *testing.T, defaultSchema, customSchema *jsonschema.Schema) {
	t.Helper()
	defRaw, err := json.Marshal(defaultSchema)
	if err != nil {
		t.Fatalf("marshal default: %v", err)
	}
	cusRaw, err := json.Marshal(customSchema)
	if err != nil {
		t.Fatalf("marshal custom: %v", err)
	}
	var defMap, cusMap map[string]any
	if err := json.Unmarshal(defRaw, &defMap); err != nil {
		t.Fatalf("unmarshal default: %v", err)
	}
	if err := json.Unmarshal(cusRaw, &cusMap); err != nil {
		t.Fatalf("unmarshal custom: %v", err)
	}
	stripEnumFromSignalsTruncatedReasons(cusMap)
	cleanCusRaw, err := json.Marshal(cusMap)
	if err != nil {
		t.Fatalf("marshal cleaned custom: %v", err)
	}
	var defNorm, cusNorm any
	if err := json.Unmarshal(defRaw, &defNorm); err != nil {
		t.Fatalf("unmarshal defNorm: %v", err)
	}
	if err := json.Unmarshal(cleanCusRaw, &cusNorm); err != nil {
		t.Fatalf("unmarshal cusNorm: %v", err)
	}
	defClean, err := json.Marshal(defNorm)
	if err != nil {
		t.Fatalf("marshal defNorm: %v", err)
	}
	cusClean, err := json.Marshal(cusNorm)
	if err != nil {
		t.Fatalf("marshal cusNorm: %v", err)
	}
	if string(defClean) != string(cusClean) {
		t.Fatalf("custom schema differs beyond enum.\ndefault cleaned: %s\ncustom cleaned: %s", defClean, cusClean)
	}
}

func stripEnumFromSignalsTruncatedReasons(node any) {
	switch v := node.(type) {
	case map[string]any:
		if field, ok := v["signals_truncated_reasons"]; ok {
			if fm, ok := field.(map[string]any); ok {
				if items, ok := fm["items"].(map[string]any); ok {
					delete(items, "enum")
				}
			}
		}
		for _, child := range v {
			stripEnumFromSignalsTruncatedReasons(child)
		}
	case []any:
		for _, child := range v {
			stripEnumFromSignalsTruncatedReasons(child)
		}
	}
}
