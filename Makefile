.PHONY: all deadband deadband-web deadband-web-windows web test vet clean

BINDIR := bin

all: deadband

deadband:
	CGO_ENABLED=0 go build -o $(BINDIR)/deadband ./cmd/deadband/

web:
	cd web && npm ci && npm run build

deadband-web: web
	mkdir -p pkg/server/static
	cp -r web/out/* pkg/server/static/
	CGO_ENABLED=0 go build -tags embed_web -o $(BINDIR)/deadband ./cmd/deadband/
	rm -rf pkg/server/static

# Cross-compiled Windows builds with the embedded web UI. Produces both
# amd64 and arm64 .exe binaries from a single web-build pass.
deadband-web-windows: web
	mkdir -p pkg/server/static
	cp -r web/out/* pkg/server/static/
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -tags embed_web -o $(BINDIR)/deadband-windows-amd64.exe ./cmd/deadband/
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -tags embed_web -o $(BINDIR)/deadband-windows-arm64.exe ./cmd/deadband/
	rm -rf pkg/server/static

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf $(BINDIR)
	rm -rf pkg/server/static
