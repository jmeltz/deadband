.PHONY: all deadband test vet clean

BINDIR := bin

all: deadband

deadband:
	CGO_ENABLED=0 go build -o $(BINDIR)/deadband ./cmd/deadband/

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf $(BINDIR)
