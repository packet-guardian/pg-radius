NAME := pg-radius
DESC := Radius HTTP auth server
VERSION ?= $(shell git describe --tags --always --dirty)
GOVERSION := $(shell go version)
BUILDTIME ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
BUILDER ?= $(shell echo "`git config user.name` <`git config user.email`>")
CGO_ENABLED ?= 0

PWD := $(shell pwd)

LDFLAGS := -X 'main.version=$(VERSION)' \
                        -X 'main.buildTime=$(BUILDTIME)' \
                        -X 'main.builder=$(BUILDER)' \
                        -X 'main.goversion=$(GOVERSION)'

.PHONY: build build-cmd

build:
	docker run \
		--rm \
		-v "$(PWD)":/usr/src/myapp \
		-w /usr/src/myapp \
		--user 1000:1000 \
		-e XDG_CACHE_HOME=/tmp/.cache \
		-e "BUILDER=$(BUILDER)" \
		-e "VERSION=$(VERSION)" \
		-e "BUILDTIME=$(BUILDTIME)" \
		golang:1.17 \
		make build-cmd

build-cmd:
	go build -o bin/pg-radius -v -ldflags "$(LDFLAGS)" -tags '$(BUILDTAGS)' ./cmd/pg-radius/...
