# Quickstart

## Prerequisites

- Go 1.23+
- Make

## Run locally

```bash
git clone https://github.com/Schildkrote/oiaf.git
cd oiaf
make dev
```

The server starts on http://127.0.0.1:8080.

## Admin token

On first run, a random admin token is generated and stored in `.oiaf/admin-token`.

## Open the UI

Navigate to http://127.0.0.1:8080 and enter the admin token.

## Use the CLI

```bash
export OIAF_ADMIN_TOKEN=$(cat .oiaf/admin-token)
go run ./cli/oiafctl identity list
```

## Run e2e tests

```bash
make e2e
```

## Stop

Press Ctrl+C to stop the server.
