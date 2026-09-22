# pdguard — developer entry points.
#
# There is no Go toolchain on the development hosts for this project, so every
# Go command goes through scripts/go.sh, which runs it inside golang:1.25.
# That also means `make` itself only ever needs bash, docker and coreutils —
# which is exactly what git bash on Windows provides.
#
# Run `make` with no target for the list.

SHELL := /usr/bin/env bash

# Stamped into the binary and used as the image tag. Falls back to "dev"
# outside a git checkout (the solution archive is not a repository).
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE   ?= pdguard:$(VERSION)
PORT    ?= 8080

GO      := bash scripts/go.sh
GOFMT   := bash scripts/gofmt.sh

# The staging directory for `make zip`, and the archive it produces.
STAGE   := dist/pdguard
ARCHIVE := dist/pdguard-solution.zip

# Paths that must never reach the solution archive (section 7.1: source only —
# no dependency, build or service directories, no large files).
ARCHIVE_EXCLUDES := \
	--exclude=./.git --exclude=./.github --exclude=./.idea --exclude=./.vscode \
	--exclude=./dist --exclude=./bin --exclude=./build --exclude=./out \
	--exclude=./vendor --exclude=./node_modules --exclude=./datasets \
	--exclude=./testdata/large \
	--exclude=./ds.pdf --exclude=./ds.txt \
	'--exclude=*.exe' '--exclude=*.test' '--exclude=*.zip' '--exclude=*.tar.gz' \
	'--exclude=*.out' '--exclude=*.prof' '--exclude=*.pprof' '--exclude=*.jsonl' \
	--exclude=.DS_Store --exclude=Thumbs.db

.DEFAULT_GOAL := help
.PHONY: help build test race lint run docker docker-run smoke bench zip clean

help: ## Show this list
	@echo "pdguard $(VERSION)"
	@echo
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

build: ## Compile every package (catches breakage without running tests)
	$(GO) build ./...

test: ## Run the full test suite with the cache disabled
	$(GO) test ./... -count=1

race: ## Run the tests under the race detector (slower image, needs cgo)
	$(GO) test ./... -count=1 -race

lint: ## go vet plus a gofmt check; fails if any file is unformatted
	$(GO) vet ./...
	@out=$$($(GOFMT) -l cmd internal); \
	if [ -n "$$out" ]; then \
		echo "gofmt needed in:"; echo "$$out"; exit 1; \
	fi; \
	echo "gofmt: clean"

run: ## Run from source in a container on port 8080 (dev loop, no image build; PORT= to change)
	@MSYS_NO_PATHCONV=1 docker run --rm -it \
		-p $(PORT):8080 \
		-v "$$(pwd -W 2>/dev/null || pwd):/src" \
		-v pdguard-gocache:/root/.cache/go-build \
		-v pdguard-gomod:/go/pkg/mod \
		-e CGO_ENABLED=0 -e PDGUARD_ADDR=":8080" \
		-w /src golang:1.25-alpine \
		go run ./cmd/server

docker: ## Build the production image, tagged pdguard:VERSION and pdguard:latest
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) -t pdguard:latest .

docker-run: docker ## Build the image and run it on port 8080 (PORT= to change)
	docker run --rm -p $(PORT):8080 --name pdguard-run $(IMAGE)

smoke: ## Bring the stack up with docker compose and verify the mask/unmask round trip
	bash scripts/smoke.sh

bench: ## Run the Go benchmarks (no tests, allocations reported)
	$(GO) test ./... -run '^$$' -bench . -benchmem

zip: ## Package the solution archive per section 7.1 (source only, no build output)
	@# Delegated to scripts/zip.sh so packaging also works where make is absent
	@# (a stock git bash on Windows), and so the exclusion list lives in one place.
	@bash scripts/zip.sh

clean: ## Remove build output and the solution archive
	rm -rf dist bin
