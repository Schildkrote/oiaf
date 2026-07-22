# Governance

This document describes how the Open Identity Access Firewall (OIAF) project is
governed.

## Maintainers

Maintainers are listed in [MAINTAINERS.md](MAINTAINERS.md). They hold merge
rights and steward the project's direction, quality, and security.

## Decision Process

The project operates on **lazy consensus**:

- Proposals are raised via issue or RFC.
- If no maintainer objects within the review window (default one week), the
  proposal is accepted.
- Objections must include reasoning and a path toward resolution.
- When consensus cannot be reached, maintainers vote; a simple majority wins.

## Release Process

- Releases follow [Semantic Versioning](https://semver.org/).
- A maintainer cuts a release from `main` and tags it.
- Each release updates [CHANGELOG.md](CHANGELOG.md).
- Security releases may be issued out of band.

## Conflict Resolution

- Technical disagreements are resolved through discussion and, if needed,
  maintainer vote.
- Conduct issues are handled per [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- Unresolvable conflicts may be escalated to the project lead.

## Contribution Ladder

1. **Contributor** — anyone with a merged contribution.
2. **Committer** — trusted contributors granted write access to specific areas.
3. **Maintainer** — committers with project-wide merge rights and governance
   responsibilities.

Advancement is by demonstrated, sustained contribution and maintainer consensus.
