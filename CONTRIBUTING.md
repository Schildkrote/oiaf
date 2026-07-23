# Contributing to OIAF

Thanks for your interest in contributing to the Open Identity Access Firewall.

## Development Setup

OIAF requires Go 1.23+.

```bash
git clone https://github.com/oiaf/oiaf.git
cd oiaf
make setup
make dev
```

## Coding Standards

- Format all Go code with `gofmt`.
- Keep the tree clean under `go vet`.
- Write table-driven tests for new logic.
- Prefer small, focused packages and explicit error handling.
- Do not introduce external dependencies without discussion.

## Commit Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(policy): add network-location condition
fix(risk): correct velocity window calculation
docs: clarify adapter SDK contract
```

## Pull Request Checklist

- [ ] Code is formatted (`gofmt`) and passes `go vet`
- [ ] Tests added or updated, table-driven where applicable
- [ ] No secrets, credentials, or PII committed
- [ ] Documentation updated for user-facing changes
- [ ] Commit messages follow Conventional Commits
- [ ] CI passes

## RFC Process

Substantial changes (new adapters, protocol changes, policy schema changes,
breaking API changes) require an RFC:

1. Open an issue describing the problem and proposed approach.
2. Draft the RFC document and link it from the issue.
3. Allow a review window of at least one week.
4. A maintainer merges the RFC once consensus is reached.

## Security Review

Changes touching authentication, risk scoring, MFA, policy evaluation, or
audit integrity require review from a security-aware maintainer. See
[SECURITY.md](SECURITY.md).

## DCO Sign-off

All contributions must include a Developer Certificate of Origin sign-off. Use
`git commit -s` to add the `Signed-off-by` trailer:

```
Signed-off-by: Jane Doe <jane@example.com>
```

By signing off, you certify that you have the right to submit the contribution
under the project's Apache-2.0 license.
