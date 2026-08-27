.PHONY: fmt vet test race build scan clean

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

scan: build
	./bin/technograph -output output.json domains.txt

clean:
	rm -f bin/technograph coverage.out report.json

