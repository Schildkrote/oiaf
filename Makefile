.PHONY: help setup dev run build install install-pam install-server test lint fmt vet e2e verify clean docker-build compose-up compose-down logs docs gen

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

install-pam: build ## Install the PAM helper on this (client) host
	sudo install -m 0755 -o root -g root bin/oiaf-pam-helper /usr/local/bin/
	sudo bash adapters/pam/oiaf-pam-install.sh /usr/local/bin/oiaf-pam-helper

install-server: build ## Install oiafd + oiafctl and the systemd unit (server host)
	sudo install -m 0755 -o root -g root bin/oiafd bin/oiafctl /usr/local/bin/
	sudo useradd --system --create-home --home /var/lib/oiaf --shell /usr/sbin/nologin oiaf
	sudo install -d -o oiaf -g oiaf -m 0750 /var/lib/oiaf
	sudo install -d -o root -g oiaf -m 0750 /etc/oiaf
	sudo install -m 0640 -o root -g oiaf deploy/systemd/oiafd.env /etc/oiaf/oiafd.env
	sudo install -m 0644 deploy/systemd/oiafd.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable oiafd
	@echo "server installed — start with: sudo systemctl start oiafd"

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
