.PHONY: fmt vet test race build scan release-check snapshot clean

fmt:
	go fmt ./...

vet:
	go vet ./...

test:
	go test ./...

race:
	go test -race ./...

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
