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

define make_artifact
	rm -rf _output
	GOOS=$(1) GOARCH=$(2) make binaries
	(cd _output/bin; tar --sort=name --mtime="@${SOURCE_DATE_EPOCH}" \
		--owner=0 --group=0 --numeric-owner \
		--pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
		-czvf ../../_artifacts/vexllm-$(VERSION).$(1)-$(2).tar.gz .)
endef

.PHONY: artifacts
artifacts:
	rm -rf _artifacts
	mkdir -p _artifacts
	$(call make_artifact,linux,amd64)
	$(call make_artifact,linux,arm64)
	$(call make_artifact,darwin,amd64)
	$(call make_artifact,darwin,arm64)
	(cd _artifacts ; sha256sum *) > SHA256SUMS
	mv SHA256SUMS _artifacts/SHA256SUMS
	touch -d @$(SOURCE_DATE_EPOCH) _artifacts/*

.PHONY: artifacts.docker
artifacts.docker:
	$(DOCKER_BUILD) --output=./_artifacts --target=artifacts .
