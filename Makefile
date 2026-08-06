SHELL := /bin/sh

.DEFAULT_GOAL := help

GO ?= go
CARGO ?= cargo
CORPUS ?= https://developer.arm.com/-/cdn-downloads/permalink/Exploration-Tools-A64-ISA/ISA_A64/ISA_A64_xml_A_profile-2026-06.tar.gz
BENCHTIME ?= 1s
BENCHCOUNT ?= 1
ITERATIONS ?= 1000000
X86_CORPUS ?=
X86_RUST_OUT ?= ./output-x86-rs
GO_OUT ?= ./output
RUST_OUT ?= ./output-rs
ASL ?= ../arm-asl-parser/asl
COVERAGE_TOOL ?= $(GO) run github.com/vladopajic/go-test-coverage/v2@v2.18.9

.PHONY: \
	help fmt-check vet test test-race coverage-source coverage-encodings verify \
	bench bench-micro bench-rust-decoder bench-x86 bench-x86-rust \
	generate-go generate-rust generate-x86-rust build \
	conformance-go conformance-rust conformance-disasm conformance \
	conformance-strict-go conformance-strict-rust conformance-strict-disasm \
	conformance-strict audit-disasm conformance-asl release-check clean

help: ## List available targets
	@awk 'BEGIN {FS = ":.*## "; printf "Usage: make <target> [VARIABLE=value ...]\n\nTargets:\n"} /^[a-zA-Z0-9_.-]+:.*## / {printf "  %-28s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

fmt-check: ## Require all Go sources to be gofmt-clean
	@unformatted="$$(find cmd pkg tests templates -type f -name '*.go' -exec gofmt -l {} +)"; \
	test -z "$$unformatted" || { \
		echo "gofmt required:" >&2; \
		echo "$$unformatted" >&2; \
		exit 1; \
	}

vet: ## Run Go static analysis
	$(GO) vet ./...

test: ## Run the deterministic offline test suite
	$(GO) test ./... -count=1 -timeout 180s

test-race: ## Run race-sensitive core and conformance packages
	$(GO) test -race ./pkg/decoder ./pkg/arm ./pkg/x86 ./pkg/coverage ./tests/conformance

coverage-source: ## Measure source coverage and enforce configured floors
	mkdir -p .coverage
	$(GO) test ./... -coverprofile=.coverage/coverage.out -covermode=atomic -coverpkg=./...
	$(COVERAGE_TOOL) --config=.testcoverage.yml
	$(GO) test ./pkg/coverage -coverprofile=.coverage/coverage-package.out -covermode=atomic
	$(COVERAGE_TOOL) --profile=.coverage/coverage-package.out \
		--threshold-file=100 --threshold-package=100 --threshold-total=100

coverage-encodings: ## Prove complete Go and Rust exact-ledger coverage
	MKASM_CORPUS="$(CORPUS)" MKASM_LEDGER_COVERAGE=1 \
		$(GO) test ./tests/conformance \
		-run '^TestGeneratedLedgerEncodingCoverage$$' -v -count=1 -timeout 300s

verify: ## Run formatting, vet, tests, race, and coverage gates
	@$(MAKE) --no-print-directory fmt-check
	@$(MAKE) --no-print-directory vet
	@$(MAKE) --no-print-directory test
	@$(MAKE) --no-print-directory test-race
	@$(MAKE) --no-print-directory coverage-source
	@$(MAKE) --no-print-directory coverage-encodings

bench: ## Run corpus-scale public API benchmarks
	MKASM_BENCH_CORPUS="$(CORPUS)" $(GO) test ./tests/benchmarks \
		-run '^$$' -bench . -benchmem -benchtime "$(BENCHTIME)" -count "$(BENCHCOUNT)"

bench-micro: ## Run parser hot-path microbenchmarks
	$(GO) test ./pkg/arm -run '^$$' \
		-bench '^Benchmark(ParseIForm|ParseAsmTemplate|PseudocodeParser|TarCorpusPreparedIFormLookup)$$' \
		-benchmem -benchtime "$(BENCHTIME)" -count "$(BENCHCOUNT)"

bench-rust-decoder: generate-rust ## Benchmark generated Rust decode time and allocations
	cd "$(RUST_OUT)" && $(CARGO) run --release --quiet --example decode_bench -- "$(ITERATIONS)"

bench-x86: ## Benchmark the x86 codec against opcodesDB v3 (X86_CORPUS=...json.xz)
	@test -n "$(X86_CORPUS)" || { echo "X86_CORPUS is required" >&2; exit 2; }
	MKASM_X86_OPCODESDB="$(X86_CORPUS)" $(GO) test ./pkg/x86 -run '^$$' \
		-bench '^Benchmark(DecodeCorpus|Encode)$$' -benchmem \
		-benchtime "$(BENCHTIME)" -count "$(BENCHCOUNT)"

bench-x86-rust: generate-x86-rust ## Benchmark the generated x86 Rust decoder
	cd "$(X86_RUST_OUT)" && $(CARGO) run --release --quiet --example decode_bench -- "$(ITERATIONS)"

generate-go: ## Generate and test the standalone Go project
	$(GO) run ./cmd/mkasm --codegen go --output "$(GO_OUT)" "$(CORPUS)"
	cd "$(GO_OUT)" && $(GO) test ./...

generate-rust: ## Generate and test the standalone Rust crate
	$(GO) run ./cmd/mkasm --codegen rust --output "$(RUST_OUT)" "$(CORPUS)"
	cd "$(RUST_OUT)" && RUSTFLAGS="-D warnings" $(CARGO) test

generate-x86-rust: ## Generate and test x86 Rust (X86_CORPUS=...json.xz)
	@test -n "$(X86_CORPUS)" || { echo "X86_CORPUS is required" >&2; exit 2; }
	xz -dc "$(X86_CORPUS)" | $(GO) run ./cmd/mkasm --arch x86_64 \
		--codegen rust --output "$(X86_RUST_OUT)" -
	cd "$(X86_RUST_OUT)" && RUSTFLAGS="-D warnings" $(CARGO) test

build: ## Build and package mkasm for the current platform
	@set -eu; \
	version="$${VERSION:-$$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"; \
	goos="$${GOOS:-$$($(GO) env GOOS)}"; \
	goarch="$${GOARCH:-$$($(GO) env GOARCH)}"; \
	artifact_version="$$(printf '%s' "$$version" | tr '/ ' '--')"; \
	package="mkasm_$${artifact_version}_$${goos}_$${goarch}"; \
	mkdir -p dist; \
	GOOS="$$goos" GOARCH="$$goarch" $(GO) build -trimpath \
		-ldflags "-s -w -X main.version=$$version" -o dist/mkasm ./cmd/mkasm; \
	./dist/mkasm --version; \
	package_dir="$$(mktemp -d "$${TMPDIR:-/tmp}/mkasm-release.XXXXXX")"; \
	trap 'rm -rf "$$package_dir"' EXIT HUP INT TERM; \
	cp dist/mkasm LICENSE README.md "$$package_dir/"; \
	tar -C "$$package_dir" -czf "dist/$${package}.tar.gz" mkasm LICENSE README.md; \
	if command -v shasum >/dev/null 2>&1; then \
		shasum -a 256 "dist/$${package}.tar.gz" > "dist/$${package}.tar.gz.sha256"; \
	elif command -v sha256sum >/dev/null 2>&1; then \
		sha256sum "dist/$${package}.tar.gz" > "dist/$${package}.tar.gz.sha256"; \
	else \
		echo "release: shasum or sha256sum is required" >&2; \
		exit 1; \
	fi; \
	printf 'release: dist/%s.tar.gz\n' "$$package"

conformance-go: ## Check Go exact-encoder byte parity against LLVM
	MKASM_CORPUS="$(CORPUS)" \
	MKASM_CLANG="$${MKASM_CLANG:-}" MKASM_LLVM_MC="$${MKASM_LLVM_MC:-}" \
	MKASM_GO_LLVM_CONFORMANCE=1 \
		$(GO) test ./tests/conformance \
		-run '^TestGoAssemblerLLVMConformance$$' -v -count=1 -timeout 600s

conformance-rust: ## Check typed and exact Rust encoder byte parity against LLVM
	MKASM_CORPUS="$(CORPUS)" \
	MKASM_CLANG="$${MKASM_CLANG:-}" MKASM_LLVM_MC="$${MKASM_LLVM_MC:-}" \
	MKASM_RUST_LLVM_CONFORMANCE=1 \
		$(GO) test ./tests/conformance \
		-run '^TestRustAssemblerLLVMConformance$$' -v -count=1 -timeout 600s

conformance-disasm: ## Check word-to-text-to-LLVM byte parity
	MKASM_CORPUS="$(CORPUS)" \
	MKASM_CLANG="$${MKASM_CLANG:-}" MKASM_LLVM_MC="$${MKASM_LLVM_MC:-}" \
	MKASM_DISASM_LLVM_PARITY=1 \
		$(GO) test ./tests/conformance \
		-run '^TestDisasmAssemblesBack$$' -v -count=1 -timeout 600s

conformance: ## Run supported Go, Rust, and disassembler LLVM parity
	@$(MAKE) --no-print-directory conformance-go
	@$(MAKE) --no-print-directory conformance-rust
	@$(MAKE) --no-print-directory conformance-disasm

conformance-strict-go: ## Require LLVM coverage for every generated Go encoding
	MKASM_LLVM_REQUIRE_ALL=1 $(MAKE) --no-print-directory conformance-go

conformance-strict-rust: ## Require LLVM coverage for every generated Rust encoding
	MKASM_LLVM_REQUIRE_ALL=1 $(MAKE) --no-print-directory conformance-rust

conformance-strict-disasm: ## Require LLVM coverage for every printable encoding
	MKASM_DISASM_REQUIRE_ALL=1 $(MAKE) --no-print-directory conformance-disasm

conformance-strict: ## Run all-opcode LLVM coverage and byte-parity gates
	@$(MAKE) --no-print-directory conformance-strict-go
	@$(MAKE) --no-print-directory conformance-strict-rust
	@$(MAKE) --no-print-directory conformance-strict-disasm

audit-disasm: ## Run the historical disassembler threshold report
	MKASM_DISASM_AUDIT=1 $(MAKE) --no-print-directory conformance-disasm

conformance-asl: ## Cross-check opcode bits and fields against Arm ASL
	@test -f "$(ASL)/arm_instrs.asl"
	@test -f "$(ASL)/arch_decode.asl"
	MKASM_CORPUS="$(CORPUS)" \
	MKASM_ASL_INSTRS="$(ASL)/arm_instrs.asl" \
	MKASM_ASL_DECODE="$(ASL)/arch_decode.asl" \
		$(GO) test ./pkg/asl ./tests/conformance \
		-run 'Corpus|Coverage|CrossCheck' -v -count=1

release-check: ## Verify, build, generate projects, and run LLVM parity
	@test -n "$(X86_CORPUS)" || { echo "X86_CORPUS is required for the release gate" >&2; exit 2; }
	@$(MAKE) --no-print-directory verify
	@$(MAKE) --no-print-directory build
	@$(MAKE) --no-print-directory generate-go
	@$(MAKE) --no-print-directory generate-rust
	@$(MAKE) --no-print-directory generate-x86-rust X86_CORPUS="$(X86_CORPUS)"
	@$(MAKE) --no-print-directory conformance

clean: ## Remove generated projects and local verification output
	rm -rf ./output ./output-rs ./aarch64-go ./aarch64-rs ./dist ./.coverage
