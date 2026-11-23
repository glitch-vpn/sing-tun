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
	@gofumpt -l -w .
	@gofmt -s -w .
	@gci write --custom-order -s standard -s "prefix(github.com/sagernet/)" -s "default" .

fmt_install:
	go install -v mvdan.cc/gofumpt@latest
	go install -v github.com/daixiang0/gci@latest

# Reports only what the fork added after upstream's v0.4.28, as the glitch
# workflow does.
lint:
	GOOS=linux golangci-lint run --new-from-rev=v0.4.28 .
	GOOS=android golangci-lint run --new-from-rev=v0.4.28 .
	GOOS=windows golangci-lint run --new-from-rev=v0.4.28 .
	GOOS=darwin golangci-lint run --new-from-rev=v0.4.28 .
	GOOS=freebsd golangci-lint run --new-from-rev=v0.4.28 .

lint_install:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint/v2/cmd/golangci-lint@v2.15.0

test:
	go build -v .
	#go test -v .
