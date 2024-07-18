# Files are installed under $(DESTDIR)/$(PREFIX)
PREFIX ?= /usr/local
DEST := $(shell echo "$(DESTDIR)/$(PREFIX)" | sed 's:///*:/:g; s://*$$::')

VERSION ?=$(shell git describe --match 'v[0-9]*' --dirty='.m' --always --tags)
VERSION_SYMBOL := github.com/AkihiroSuda/vexllm/cmd/vexllm/version.Version

export CGO_ENABLED ?= 0
export DOCKER_BUILDKIT := 1
export SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)

GO ?= go
GO_LDFLAGS ?= -s -w -X $(VERSION_SYMBOL)=$(VERSION)
GO_BUILD ?= $(GO) build -trimpath -ldflags="$(GO_LDFLAGS)"
DOCKER ?= docker
DOCKER_BUILD ?= $(DOCKER) build --build-arg SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH)

.PHONY: all
all: binaries

.PHONY: binaries
binaries: _output/bin/vexllm

.PHONY: _output/bin/vexllm
_output/bin/vexllm:
	$(GO_BUILD) -o $@ ./cmd/vexllm

.PHONY: install
install: uninstall
	mkdir -p "$(DEST)"
	install _output/bin/vexllm "$(DEST)/bin/vexllm"

.PHONY: uninstall
uninstall:
	rm -rf "$(DEST)/bin/vexllm"

.PHONY: clean
clean:
	rm -rf _output _artifacts

.PHONY: artifacts
artifacts:
	rm -rf _artifacts
	mkdir -p _artifacts
	GOOS=linux  GOARCH=amd64            $(GO_BUILD) -o _artifacts/vexllm-$(VERSION).linux-amd64   ./cmd/vexllm
	GOOS=linux  GOARCH=arm64            $(GO_BUILD) -o _artifacts/vexllm-$(VERSION).linux-arm64   ./cmd/vexllm
	GOOS=darwin GOARCH=amd64            $(GO_BUILD) -o _artifacts/vexllm-$(VERSION).darwin-amd64  ./cmd/vexllm
	GOOS=darwin GOARCH=arm64            $(GO_BUILD) -o _artifacts/vexllm-$(VERSION).darwin-arm64  ./cmd/vexllm
	(cd _artifacts ; sha256sum *) > SHA256SUMS
	mv SHA256SUMS _artifacts/SHA256SUMS
	touch -d @$(SOURCE_DATE_EPOCH) _artifacts/*

.PHONY: artifacts.docker
artifacts.docker:
	$(DOCKER_BUILD) --output=./_artifacts --target=artifacts .
