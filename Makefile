.PHONY: all deadband release deadband-web deadband-web-windows web test vet clean capabilities check-capabilities

VERSION ?= 0.9.0
LDFLAGS := -s -w -X github.com/jmeltz/deadband/pkg/cli.Version=$(VERSION)
BUILD := CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)"

BINDIR := bin

all: deadband

deadband:
	$(BUILD) -o $(BINDIR)/deadband ./cmd/deadband/

release:
	@mkdir -p $(BINDIR)
	GOOS=linux   GOARCH=amd64 $(BUILD) -o $(BINDIR)/deadband-linux-amd64       ./cmd/deadband/
	GOOS=linux   GOARCH=arm64 $(BUILD) -o $(BINDIR)/deadband-linux-arm64       ./cmd/deadband/
	GOOS=darwin  GOARCH=arm64 $(BUILD) -o $(BINDIR)/deadband-darwin-arm64      ./cmd/deadband/
	GOOS=darwin  GOARCH=amd64 $(BUILD) -o $(BINDIR)/deadband-darwin-amd64      ./cmd/deadband/
	GOOS=windows GOARCH=amd64 $(BUILD) -o $(BINDIR)/deadband-windows-amd64.exe ./cmd/deadband/
	GOOS=windows GOARCH=arm64 $(BUILD) -o $(BINDIR)/deadband-windows-arm64.exe ./cmd/deadband/
	@echo "built deadband v$(VERSION):"
	@ls -lh $(BINDIR)/deadband-*

web:
	cd web && npm ci && npm run build

deadband-web: web
	mkdir -p pkg/server/static
	cp -r web/out/* pkg/server/static/
	$(BUILD) -tags embed_web -o $(BINDIR)/deadband ./cmd/deadband/
	rm -rf pkg/server/static

# Cross-compiled Windows builds with the embedded web UI. Produces both
# amd64 and arm64 .exe binaries from a single web-build pass.
deadband-web-windows: web
	mkdir -p pkg/server/static
	cp -r web/out/* pkg/server/static/
	GOOS=windows GOARCH=amd64 $(BUILD) -tags embed_web -o $(BINDIR)/deadband-windows-amd64.exe ./cmd/deadband/
	GOOS=windows GOARCH=arm64 $(BUILD) -tags embed_web -o $(BINDIR)/deadband-windows-arm64.exe ./cmd/deadband/
	rm -rf pkg/server/static

test:
	go test ./...

vet:
	go vet ./...

capabilities:
	go run ./cmd/query-capabilities

check-capabilities:
	go run ./cmd/query-capabilities --check

clean:
	rm -rf $(BINDIR)
	rm -rf pkg/server/static
