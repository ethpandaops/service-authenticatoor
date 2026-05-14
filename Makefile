SHELL := /bin/bash

BINARY  := authenticatoor
RELEASE ?= dev
OUT_DIR := bin

GIT_SHA := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X main.version=$(RELEASE) -X main.gitSHA=$(GIT_SHA)

ifeq ($(OS),Windows_NT)
	BINARY_EXT := .exe
endif

.PHONY: build test vet fmt-check lint clean start-dev

build:
	@mkdir -p $(OUT_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(OUT_DIR)/$(BINARY)$(BINARY_EXT) ./cmd/authenticatoor

# start-dev runs the service against .hack/local/config.yaml, which binds
# :18080 and serves http://auth.localhost:18080 with CF Access verification
# disabled. The signing key is generated on first run into .hack/local/.
start-dev:
	@.hack/local/run.sh

test:
	go test -race ./...

vet:
	go vet ./...

fmt-check:
	@if [ "$$(gofmt -s -l . | wc -l)" -gt 0 ]; then \
		echo "files need gofmt:"; gofmt -s -l .; exit 1; \
	fi

lint: vet fmt-check

clean:
	rm -rf $(OUT_DIR)
