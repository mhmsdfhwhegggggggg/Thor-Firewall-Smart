# ═══════════════════════════════════════════════════════════════════════════════
# Thor Firewall Smart — Production Makefile
# ═══════════════════════════════════════════════════════════════════════════════
.DEFAULT_GOAL := help
.PHONY: help dev build build-bpf test test-unit bench lint fmt audit deny \
        clean docker-build docker-push docker-up docker-down certs \
        k8s-deploy helm-install ml-train sbom release version

REGISTRY    ?= ghcr.io
REPO_OWNER  ?= mhmsdfhwhegggggggg
IMAGE_PREFIX := $(REGISTRY)/$(REPO_OWNER)/thor
VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.3.0-dev")
GIT_COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE  := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
CARGO       := cargo
DOCKER      := docker
KUBECTL     := kubectl
AGENTS      := thor-agent thor-agent-net thor-agent-web thor-agent-srv thor-soc-slm
B := \033[1m
G := \033[0;32m
C := \033[0;36m
R := \033[0m

help: ## Show all targets
	@printf "\n$(B)🛡️  Thor Firewall Smart$(R) — Version: $(VERSION)\n\n"
	@awk 'BEGIN{FS=":.*##"} /^[a-zA-Z_-]+:.*?##/{printf "  $(G)%-22s$(R) %s\n",$$1,$$2}' $(MAKEFILE_LIST)

dev: ## Bootstrap dev environment
	@printf "$(B)▶ Dev bootstrap...$(R)\n"
	$(CARGO) install cargo-audit cargo-deny cargo-criterion 2>/dev/null || true
	$(MAKE) build
	@printf "$(G)✓ Ready$(R)\n"

build: ## Release build — all user-space crates
	@printf "$(B)▶ Building release...$(R)\n"
	CARGO_INCREMENTAL=0 $(CARGO) build --release \
		-p thor-common -p thor-agent -p thor-agent-net \
		-p thor-agent-web -p thor-agent-srv -p thor-soc-slm \
		-p thor-script -p thor-ids
	@printf "$(G)✓ Build OK$(R)\n"

build-bpf: ## Build eBPF kernel programs (needs bpf toolchain)
	CARGO_INCREMENTAL=0 $(CARGO) build --release \
		-p thor-bpf -p thor-xdp-ebpf \
		--target bpfel-unknown-none -Z build-std=core
	@printf "$(G)✓ eBPF build OK$(R)\n"

test: ## Run all tests
	$(MAKE) test-unit

test-unit: ## Unit tests (no kernel required)
	$(CARGO) test --lib \
		-p thor-common -p thor-script -p thor-ids \
		-- --nocapture

bench: ## Run Criterion benchmarks
	$(CARGO) bench -p thor-ids -p thor-common

lint: ## Clippy on all user-space crates
	$(CARGO) clippy \
		-p thor-common -p thor-agent-net -p thor-agent-web \
		-p thor-agent-srv -p thor-soc-slm -p thor-ids \
		-- -D warnings -A clippy::too_many_arguments

fmt: ## Format all code
	$(CARGO) fmt --all

fmt-check: ## Check formatting (CI)
	$(CARGO) fmt --all -- --check

audit: ## Security audit of dependencies
	$(CARGO) audit

deny: ## License + banned crate check
	$(CARGO) deny check

docker-build: ## Build all Docker images
	@for agent in $(AGENTS); do \
		printf "  $(C)Building $$agent...$(R)\n"; \
		$(DOCKER) build \
			--build-arg BUILD_DATE=$(BUILD_DATE) \
			--build-arg GIT_COMMIT=$(GIT_COMMIT) \
			--build-arg VERSION=$(VERSION) \
			--build-arg AGENT_NAME=$$agent \
			-t $(IMAGE_PREFIX)/$$agent:$(VERSION) \
			-t $(IMAGE_PREFIX)/$$agent:latest \
			-f crates/$$agent/Dockerfile . 2>/dev/null || \
		$(DOCKER) build \
			--build-arg BUILD_DATE=$(BUILD_DATE) \
			--build-arg GIT_COMMIT=$(GIT_COMMIT) \
			--build-arg VERSION=$(VERSION) \
			--target runtime -t $(IMAGE_PREFIX)/$$agent:$(VERSION) .; \
	done
	@printf "$(G)✓ All images built$(R)\n"

docker-push: ## Push images to GHCR
	@echo "$$GITHUB_TOKEN" | $(DOCKER) login $(REGISTRY) -u $(REPO_OWNER) --password-stdin
	@for agent in $(AGENTS); do \
		$(DOCKER) push $(IMAGE_PREFIX)/$$agent:$(VERSION); \
		$(DOCKER) push $(IMAGE_PREFIX)/$$agent:latest; \
	done

docker-up: ## Start dev stack
	docker compose -f docker-compose.dev.yml up -d

docker-down: ## Stop all containers
	docker compose down --remove-orphans

certs: ## Generate mTLS certificates
	bash scripts/generate_certs.sh

k8s-deploy: ## Deploy to Kubernetes
	$(KUBECTL) apply -f k8s/namespace.yaml
	$(KUBECTL) apply -f k8s/thor-secrets.yaml
	$(KUBECTL) apply -f k8s/

helm-install: ## Install via Helm chart
	helm upgrade --install thor-firewall helm/thor-firewall \
		--namespace thor-firewall --create-namespace

ml-train: ## Train + export ONNX models
	pip install -q numpy scikit-learn skl2onnx onnx
	python3 ml_train_export.py

sbom: ## Generate SBOM (requires syft)
	syft dir:. -o spdx-json=thor-sbom.spdx.json
	syft dir:. -o cyclonedx-json=thor-sbom.cyclonedx.json

release: lint audit deny test build ## Full release pipeline
	@printf "$(G)$(B)✓ Release $(VERSION) ready$(R)\n"

version: ## Show version info
	@printf "Version: $(VERSION) | Commit: $(GIT_COMMIT) | Date: $(BUILD_DATE)\n"

clean: ## Clean build artifacts
	$(CARGO) clean
	rm -rf certs/ *.spdx.json *.cyclonedx.json
