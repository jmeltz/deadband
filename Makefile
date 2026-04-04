.PHONY: all deadband deadband-web web test vet clean

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

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf $(BINDIR)
	rm -rf pkg/server/static
