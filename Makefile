# kguard build file.
#
# Targets:
#   make vmlinux   generate bpf/vmlinux.h from the running kernel's BTF
#   make generate  run bpf2go to compile the eBPF C and emit Go bindings
#   make build     build the kguard binary into ./bin/kguard
#   make rules     validate the default rules
#   make clean     remove generated and built artifacts

BPFTOOL ?= bpftool
CLANG   ?= clang
GO      ?= go

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

BIN := bin/kguard

.PHONY: all
all: build

# Generate vmlinux.h (CO-RE kernel type definitions) from the live kernel BTF.
bpf/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

.PHONY: vmlinux
vmlinux: bpf/vmlinux.h

# Compile the eBPF object and generate Go bindings (kguard_bpf*.go/.o).
.PHONY: generate
generate: bpf/vmlinux.h
	$(GO) generate ./...

.PHONY: build
build: generate
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build $(LDFLAGS) -o $(BIN) ./cmd/kguard
	@echo "built $(BIN) ($(VERSION))"

.PHONY: rules
rules: build
	$(BIN) rules test -rules rules/default.yaml

# Convenience: run the monitor (needs root).
.PHONY: run
run: build
	sudo $(BIN) run -rules rules/default.yaml

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: clean
clean:
	rm -rf bin
	rm -f internal/loader/kguard_bpf*.go internal/loader/kguard_bpf*.o
	rm -f bpf/vmlinux.h
