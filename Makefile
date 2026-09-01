build:
	GOOS=darwin GOARCH=arm64 go build -v -tags with_gvisor .
	GOOS=ios GOARCH=arm64 go build -v -tags with_gvisor .
	GOOS=linux GOARCH=amd64 go build -v -tags with_gvisor .
	GOOS=linux GOARCH=arm64 go build -v -tags with_gvisor .
	GOOS=linux GOARCH=386 go build -v -tags with_gvisor .
	GOOS=linux GOARCH=arm go build -v -tags with_gvisor .
	GOOS=android GOARCH=arm64 go build -v -tags with_gvisor .
	GOOS=windows GOARCH=amd64 go build -v -tags with_gvisor .

fmt:
	@golangci-lint fmt

lint:
	GOOS=linux golangci-lint --max-same-issues=0 --max-issues-per-linter=0 run ./...
	GOOS=android golangci-lint --max-same-issues=0 --max-issues-per-linter=0 run ./...
	GOOS=windows golangci-lint --max-same-issues=0 --max-issues-per-linter=0 run ./...
	GOOS=darwin golangci-lint --max-same-issues=0 --max-issues-per-linter=0 run ./...

lint_install:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

test:
	go build -v .
	#go test -bench=. ./internal/checksum_test
	go test -v .
