.PHONY: fmt vet test race benchmark build scan release-check snapshot clean

GO_FORMAT_TOOLCHAIN ?= go1.25.7

fmt:
	GOTOOLCHAIN=$(GO_FORMAT_TOOLCHAIN) go fmt ./...

vet:
	go vet ./...

test:
	go test ./...

race:
	go test -race ./...

benchmark:
	go test -run '^$$' -bench . -benchmem ./internal/fingerprint ./internal/extract

build:
	mkdir -p bin
	go build -trimpath -o bin/technograph ./cmd/technograph
	go build -trimpath -o bin/technograph-mcp ./cmd/technograph-mcp

scan: build
	./bin/technograph -output output.json domains.txt

release-check:
	goreleaser check

snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -f bin/technograph bin/technograph-mcp coverage.out report.json
	rm -rf dist
