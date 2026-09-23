# OIAF vs Commercial Identity Security

This page compares OIAF's capabilities — as they exist **in this repository today** —
against the commercial identity-security products that solve the same problems. It is
written to be honest: OIAF is pre-release software (current tag `v0.2.1-security`), not a finished product. Where a
capability is real, functional, in progress, or only designed, the tables say so.

!!! warning "Not a drop-in replacement yet"
    OIAF is experimental pre-release software. Nothing here should be read as
    "uninstall Silverfort/Okta/Duo/CyberArk and install OIAF." If you have a
    commercial stack that meets your compliance requirements today, keep it.
    OIAF is for teams that want an open, auditable, self-hostable starting point
    and are willing to run experimental software with independent security review.

!!! note
    OIAF is an independent open-source project. It is not affiliated with or
    endorsed by any commercial identity-security vendor named on this page.

## Maturity legend

| Status | Meaning |
| --- | --- |
| :material-check-circle:{ .lg .middle style="color:#2e7d32" } **Real** | Implemented, tested, and packaged for deployment in this repo. Still pre-release; not field-hardened. |
| :material-progress-check:{ .lg .middle style="color:#1565c0" } **Functional** | Working implementation with unit tests; usable in dev/test environments, rough edges expected. |
| :material-hammer-wrench:{ .lg .middle style="color:#ef6c00" } **In progress** | Active development; interfaces may change; not recommended for any use yet. |
| :material-pencil-ruler:{ .lg .middle style="color:#6a1b9a" } **Design-stage** | RFC/documented design or skeleton code that exits with an error; no working implementation yet. |
| :material-map-marker-road:{ .lg .middle style="color:#546e7a" } **Roadmap** | Planned milestone in [ROADMAP.md](https://github.com/Schildkrote/oiaf/blob/main/ROADMAP.md); nothing implemented. |

## Capability comparison

### Risk-based access control & adaptive MFA orchestration

| Capability | OIAF status | Comparable commercial vendors | What OIAF replaces for you |
| --- | --- | --- | --- |
| Policy-driven access decisions (evaluate / challenge / verify API) | **Functional** — rule engine with thresholds, decision API, unit tests | Silverfort, Microsoft Entra ID Protection + Conditional Access, Okta Adaptive MFA/Risk, Duo Beyond MFA, PingOne Protect, CyberArk Identity, SecureAuth, OneLogin | A per-seat/per-app risk-decision licensing tier — *if* your use case fits the rule set that exists today. The engine is rule-based, not ML-based, and far narrower than any listed product. |
| Adaptive MFA orchestration (step-up on risk score) | **Functional** — challenge service wires risk result to TOTP/push step-up | Same as above | Same caveats as above: works in dev/test, single control plane, no HA story yet. |

### MFA factors

| Capability | OIAF status | Comparable commercial vendors | What OIAF replaces for you |
| --- | --- | --- | --- |
| TOTP (RFC 6238) | **Functional** — implemented with unit tests | Duo, RSA SecurID Access, IBM Verify, ForgeRock AM | Per-user MFA licensing for straightforward TOTP deployments on systems OIAF can actually reach (today: Linux PAM, dev/test). |
| Push MFA | **Functional** — implemented with unit tests; requires a companion push app you operate | Duo, RSA SecurID Access, IBM Verify, ForgeRock AM | Push licensing — but you must supply/host the push endpoint; there is no polished consumer app. |
| WebAuthn / FIDO2 | **Implemented, software-authenticator tested** — registration and assertion ceremonies are in `core/internal/mfa/webauthn.go` with 29 test functions across the MFA and API layers, plus a `webauthntest` helper. **Hardware-key validation is an open gate:** the suite exercises a software authenticator, so a physical YubiKey-class key has not been proven end to end. | Duo, RSA SecurID Access, IBM Verify, ForgeRock AM | WebAuthn factor licensing for deployments you can test with a software authenticator. Do **not** plan a phishing-resistant rollout on OIAF until hardware-key validation is demonstrated and durable storage exists (see below). |

### Linux PAM inline enforcement & sshd step-up

| Capability | OIAF status | Comparable commercial vendors | What OIAF replaces for you |
| --- | --- | --- | --- |
| `pam_exec` helper evaluating every sshd/sudo/login against the OIAF core | **Real** — helper implemented, unit-tested plus e2e coverage, systemd packaging, install scripts, field-test script. **Not yet field-tested behind a real production PAM stack.** | Silverfort, CyberArk, Delinea | A Linux PAM enforcement agent + its licensing, *for self-hosted Linux fleets you can experiment on*. Lockout risk is real; follow the documented VM-first rollout. |
| FIDO at the Linux console (the `pam_u2f` / Google pam-webauthn slice) | **Roadmap** — OIAF does not implement this; pam_u2f and pam-webauthn remain the practical open options today | pam_u2f (Yubico), Google pam-webauthn (both OSS) | Nothing — use the dedicated OSS modules for this slice. |

### Protocol-agnostic DC auth monitoring & service-account "digital fencing"

| Capability | OIAF status | Comparable commercial vendors | What OIAF replaces for you |
| --- | --- | --- | --- |
| DC-side authentication event monitoring (EvtSubscribe/ETW, no WEF, no LSASS injection) | **Design-stage** — Windows dc-agent adapter has parser/sender code and stubs; see [RFC-0001](rfcs/0001-dc-agent-service-account-discovery.md) and roadmap milestone M4 | Silverfort (the explicit benchmark for this capability), Semperis, Netwrix, Microsoft AD tiering model | Nothing yet. This is the headline Silverfort capability; OIAF has a written design and early code, not a product. |
| Service-account "digital fencing" (protect non-human identities via auth-event response) | **Roadmap (M4, RFC-0001)** | Silverfort, Semperis, Netwrix | Nothing yet. |

### AD inventory / privileged group + SPN discovery

| Capability | OIAF status | Comparable commercial vendors | What OIAF replaces for you |
| --- | --- | --- | --- |
| LDAP-based inventory scanner: privileged group membership, SPN discovery, gMSA, stale/disabled/trust flags | **Functional** — implemented against `go-ldap`, with unit tests; read-only discovery, no graph analysis | BloodHound (OSS), BloodHound Enterprise, Semperis DSP, PingCastle | Lightweight continuous inventory attributes (who is privileged, which accounts have SPNs) — *not* attack-path analysis. BloodHound's graph model has no OIAF equivalent today. |

### Hash-chained tamper-evident audit

| Capability | OIAF status | Comparable commercial vendors | What OIAF replaces for you |
| --- | --- | --- | --- |
| SHA-256 hash-chained audit event log (previous-hash linkage, hash verification) | **Functional** — implemented with unit tests; storage today is in-memory only (no durable backend wired yet) | WORM storage appliances, SIEM tamper-detection (Splunk/Elastic), Chronicle | Nothing on its own — with MemoryStore the chain dies on restart. Becomes meaningful only when a durable store lands. |

### Identity graph + risk analytics

| Capability | OIAF status | Comparable commercial vendors | What OIAF replaces for you |
| --- | --- | --- | --- |
| Identity graph, behavioral analytics, ML risk scoring | **Roadmap (M6)** | Silverfort, Microsoft Identity Protection, Semperis | Nothing. OIAF's risk engine is deterministic rules; the vendors above have years of telemetry-driven models. |

## Honest bottom line

- **What is genuinely usable now (in dev/test):** the decision API, rule-based risk engine, TOTP/push factors, the Linux PAM helper with its packaging and field-test script, the read-only AD inventory scanner, and the hash-chained audit design.
- **What is not:** WebAuthn against real hardware keys (the ceremonies are implemented and tested with a software authenticator; physical-key validation is an open gate), the Windows dc-agent and digital-fencing story (design-stage/roadmap), durable audit storage (in-memory only — nothing survives a restart), identity graph analytics (roadmap), and the Entra ID and Duo cloud-IdP adapters, which are design-stage skeletons that exit with an error. Two capabilities are implemented but **unproven against anything real**: the Okta adapter (read-only System Log ingestion + risk signals, offline-tested against a hostile mock server, never validated against a live tenant) and WebAuthn as above.
- **What OIAF will realistically replace for you today:** nothing in production. It is a foundation you can audit, extend, and experiment with — AGPL-licensed, with an architecture that targets the same problem space as the vendors above.

If you evaluate OIAF against a commercial product, treat this page as the claim
sheet: anything marked below **Functional** is not a reason to choose OIAF yet.
See [ROADMAP.md](https://github.com/Schildkrote/oiaf/blob/main/ROADMAP.md) for the
milestone plan and [AGENT_STATUS.md](https://github.com/Schildkrote/oiaf/blob/main/AGENT_STATUS.md)
for current build status.
