GO ?= go
BINARY ?= gomta
CONFIG ?= gomta.yaml
VERSION ?= dev
IMAGE ?= ferchd/gomta
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

.PHONY: all build test vet fmt tidy check run init clean docker-build docker-up docker-down docker-logs help

all: build

build:
	$(GO) build -trimpath \
		-ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)" \
		-o $(BINARY) ./cmd/gomta

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w .

tidy:
	$(GO) mod tidy

check: build
	./$(BINARY) check -config $(CONFIG)

run: build
	./$(BINARY) serve -config $(CONFIG)

# First-run setup for a local instance. Change the domain and hostname.
init: build
	./$(BINARY) init -domain example.com -hostname mail.example.com

clean:
	rm -f $(BINARY) $(BINARY).exe coverage.out
	rm -rf dist

docker-build:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):local .

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f gomta

help:
	@echo "Targets:"
	@echo "  build         Build ./$(BINARY)"
	@echo "  test          Run all tests"
	@echo "  vet           Run go vet"
	@echo "  fmt           Format all Go files"
	@echo "  tidy          Tidy go.mod/go.sum"
	@echo "  check         Build and validate $(CONFIG)"
	@echo "  run           Build and serve $(CONFIG)"
	@echo "  init          Create a local example configuration"
	@echo "  clean         Remove build artifacts"
	@echo "  docker-build  Build the container image"
	@echo "  docker-up     Start Docker Compose"
	@echo "  docker-down   Stop Docker Compose"
	@echo "  docker-logs   Follow container logs"
