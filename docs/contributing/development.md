# Development

Coding standards and testing practices for OIAF.

## Coding Standards

- Follow standard Go conventions (`gofmt`, `go vet`).
- Run `make fmt` before committing.
- No comments unless they explain *why*, not *what*.
- Use `slog` for structured logging; never log secrets.
- Tag secret fields with `json:"-"` to prevent serialization.
- Keep packages small and focused; follow the existing internal package layout.
- Use `context.Context` as the first parameter for all functions that do I/O.
- Prefer interfaces for pluggability (e.g., `storage.Store`, `risk.Engine`,
  `policy.Engine`).

## Testing

- Unit tests: `make test` (`go test ./...`)
- E2E tests: `make e2e` (bash script at `test/e2e/e2e.sh`)
- Full verification: `make verify` (fmt + vet + test + e2e)
- Write tests for new policy operators, risk rules, and MFA flows.
- Test both allow and deny paths; test edge cases (expired challenges, max
  attempts, missing fields).

## Linting

```bash
make lint     # go vet + gofmt check
```

A `.golangci.yml` is present for future golangci-lint integration.

## Commit Style

- Use conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`.
- Keep commits focused; one logical change per commit.

## Pull Requests

- Open a PR against `main`.
- Ensure `make verify` passes.
- Include tests for new functionality.
- Update docs for user-facing changes.
