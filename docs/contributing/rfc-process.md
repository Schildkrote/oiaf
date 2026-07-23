# RFC Process

Significant design changes to OIAF go through an RFC (Request for Comments)
process to ensure alignment and review before implementation.

## When to Write an RFC

- New adapters or major adapter changes
- Changes to the policy format or evaluation semantics
- New MFA methods or challenge flow changes
- Storage backend changes
- Breaking API changes
- Security-relevant design decisions

## Process

1. **Draft** — Copy the template below into `docs/rfcs/NNNN-title.md`.
2. **Open PR** — Submit the RFC as a pull request for discussion.
3. **Review** — Maintainers and community comment. Iterate on the design.
4. **Decision** — A maintainer marks the RFC as `accepted` or `rejected`.
5. **Implement** — Accepted RFCs are implemented in subsequent PRs referencing
   the RFC.

## Template

```markdown
# RFC-NNNN: Title

- **Status:** draft | accepted | rejected | implemented
- **Author:** @username
- **Created:** YYYY-MM-DD
- **Updated:** YYYY-MM-DD

## Summary

One-paragraph summary of the proposal.

## Motivation

Why is this change needed? What problem does it solve?

## Proposal

Detailed design. Include data structures, API changes, configuration, and
interaction with existing components.

## Alternatives Considered

What other approaches were evaluated and why were they rejected?

## Security Considerations

How does this affect OIAF's security posture? Reference the threat model if
applicable.

## Compatibility

Is this backward-compatible? What migration is required?

## Implementation Plan

Phases, milestones, and testing strategy.
```

## Numbering

RFCs are numbered sequentially starting at 0001. Reserve the next number by
checking existing files in `docs/rfcs/`.
