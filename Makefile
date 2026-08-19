.PHONY: help setup dev run build install test lint fmt vet e2e verify clean docker-build compose-up compose-down logs docs gen

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

setup: ## Run go mod tidy
	go mod tidy

dev: ## Run the server locally
	go run ./core/cmd/oiafd

run: dev ## Same as dev

build: ## Build oiafd, oiafctl, and oiaf-pam-helper to bin/
	go build -o bin/oiafd ./core/cmd/oiafd
	go build -o bin/oiafctl ./cli/oiafctl
	go build -o bin/oiaf-pam-helper ./adapters/pam/oiaf-pam-helper

install: ## Install all packages
	go install ./...

test: ## Run tests
	go test ./...

lint: ## Run go vet and gofmt check
	go vet ./...
	gofmt -l .

fmt: ## Format code
	gofmt -w .

vet: ## Run go vet
	go vet ./...

e2e: ## Run end-to-end tests
	bash test/e2e/e2e.sh

verify: fmt vet test e2e ## Run fmt, vet, test, and e2e

clean: ## Remove bin/ and tmp/
	rm -rf bin/ tmp/

docker-build: ## Build Docker image
	docker build -f deploy/docker/Dockerfile -t oiaf:latest .

compose-up: ## Start docker compose
	docker compose -f deploy/docker/docker-compose.yml up -d

compose-down: ## Stop docker compose
	docker compose -f deploy/docker/docker-compose.yml down

logs: ## Tail docker compose logs
	docker compose -f deploy/docker/docker-compose.yml logs -f

docs: ## Serve docs with mkdocs (if available)
	@command -v mkdocs >/dev/null 2>&1 && mkdocs serve || echo "mkdocs not installed"

gen: ## Placeholder for code generation
	@echo "code generation placeholder"
