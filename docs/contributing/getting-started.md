# Getting Started

Set up a local development environment for OIAF.

## Prerequisites

- Go 1.23+
- Make
- Git

## Clone and Build

```bash
git clone https://github.com/Schildkrote/oiaf.git
cd oiaf
make setup    # go mod tidy
make build    # builds bin/oiafd and bin/oiafctl
```

## Run the Server

```bash
make dev
```

The server starts on `http://127.0.0.1:8080`. On first run, an admin token is
generated and written to `.oiaf/admin-token`.

## Use the CLI

```bash
export OIAF_ADMIN_TOKEN=$(cat .oiaf/admin-token)
go run ./cli/oiafctl identity list
go run ./cli/oiafctl seed --dev
```

## Run Tests

```bash
make test     # unit tests
make e2e      # end-to-end tests
make verify   # fmt + vet + test + e2e
```

## Project Layout

```
core/cmd/oiafd/          Server entrypoint
core/internal/api/       HTTP handlers
core/internal/policy/    Policy engine
core/internal/risk/      Risk engine
core/internal/mfa/       TOTP and push services
core/internal/challenge/ Challenge orchestration
core/internal/audit/     Audit logging
core/internal/storage/   Storage interface and memory store
core/internal/auth/      Token auth
core/internal/config/    Configuration
cli/oiafctl/             Admin CLI
policy/examples/         Example policies
deploy/                  Docker, Helm, Terraform, Ansible
```
