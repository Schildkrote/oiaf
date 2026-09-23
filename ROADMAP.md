# Roadmap

This roadmap is directional and may change as the project evolves.

Status vocabulary used below, deliberately conservative — see
[docs/comparison.md](docs/comparison.md) for the same legend:

- **Done** — implemented, tested, and verified end-to-end.
- **Functional** — working implementation with tests; usable in dev/test. Not yet
  proven against the real infrastructure it targets.
- **Partial** — real code exists and is wired, but a required half is missing
  (tests, persistence, or the consumer that acts on its output).
- **Planned** — design exists; no implementation.

---

## M0 — Foundations — Done

- Repository scaffold and CI
- Project governance and documentation
- Core data models and interfaces

## M1 — MVP Core — Functional

- `oiafctl` CLI
- Admin UI
- Decision API (`/v1/access/evaluate`) — covered by `test/e2e.sh`
- Policy engine (JSON rules, 13 operators)
- Audit logging with SHA-256 hash chain

> **Durability caveat:** every one of the above persists to `MemoryStore` only.
> The hash chain, policies, identities and audit history are lost on restart.
> This is the single largest functional limitation in the project and gates M4
> and M6 — see **Next steps → 1. Storage driver**.

## M2 — MFA — Functional

- TOTP (RFC 6238)
- Push notifications (requires a companion push endpoint you operate)
- MFA orchestrator and challenge flow
- WebAuthn / FIDO2 — tested against a **software authenticator only**; never
  exercised with real hardware

## M3 — Core Adapters

- Adapter SDK — **Done**
- Linux PAM adapter — **Done** (fail-closed exit code asserted in `test/e2e.sh`)
- RADIUS adapter — **Planned** (14-line stub, exits 1)
- LDAP proxy adapter — **Planned** (14-line stub, exits 1)
- Okta adapter — **Done** (merged 2026-09; 91 test functions, offline-tested
  against recorded fixtures, never against a live Okta tenant)
- Entra ID / Duo / generic webhook — **Planned** (14-line stubs, exit 1)
- OIDC proxy, Kubernetes, PostgreSQL, SSH CA, Windows Credential Provider —
  **Planned**; directories contain only a README placeholder, no Go code

## M4 — DC Agent and Service Account Discovery

Current state, measured rather than estimated:

| Component | State | Evidence |
|---|---|---|
| DC agent Windows service | **Partial** | ~770 LOC; real `wevtapi.dll` / `EvtSubscribe` syscall code; runs under `svc.Run`; cross-compiles `GOOS=windows`. **Never executed on a real domain controller.** |
| Event parsing | **Done** | 13 tests; parser handles **10** event IDs |
| AD inventory scanner | **Functional** | 21 test functions as of the scanner-defect PR; LDAP integration path written but **not yet executed** |
| Service-account discovery / digital fencing | **Partial** | 325 LOC, 7 tests; real baseline/deviation logic, wired to `/v1/ad/events`. **Emits decisions that nothing consumes.** |
| AD response adapter (enforcement) | **Partial** | ~365 LOC, 4 real LDAP actions, **zero tests**, **not wired to anything** |
| WFP enforcement driver | **Planned** | RFC only; kernel-mode, separate repository |

Milestone deliverables:

- DC agent Windows Service (EvtSubscribe real-time auth monitoring on DCs)
- AD inventory scanner (LDAP enumeration, privileged group mapping, SPN discovery)
- Service account behavioural discovery engine (digital fencing)
- Baseline deviation detection and policy enforcement
- AD response adapter (account disable, force password reset, group removal)
- WFP enforcement driver (separate repo, kernel-mode network filtering)

> **Correction.** This roadmap previously listed "**ticket revocation**" as an AD
> response action. No such code exists — `adapters/ad-response` implements disable,
> enable, force-password-reset and remove-from-group only. Ticket revocation
> (Kerberos TGT invalidation) requires `kadmin`/`klist` or a PkInit path that has
> not been designed. It is recorded as planned work below, not claimed as built.

## M5 — Cloud Identity — Planned

- OIDC / SAML web app adapter
- Cloud identity provider integration
- Federated risk signals

## M6 — Identity Graph and Risk Analytics

- Risk rule engine — **Functional** (17 deterministic scoring rules, 5 risk levels,
  9 tests, wired into the decision path). Rule-based, **not** ML-based, and far
  narrower than any commercial equivalent.
- Identity graph — **Planned.** No graph code exists: no relationship model, no
  traversal, no persistence for relationships.
- Advanced risk analytics / behavioural anomaly detection — **Planned**, except
  that the discovery engine already computes per-account behavioural statistics
  (`temporalRegularity`, `sourceConsistency`, `targetConsistency`,
  `logonTypePurity`, `protocolPurity`) which are proto-anomaly signals for service
  accounts.

---

# Next steps

Ordered by dependency, not by interest. Each item states why it sits where it does,
what "done" means, and what is explicitly out of scope.

## 1. Storage driver — the shared blocker

**Why first.** `config.example.yaml` advertises `storage: driver: memory` and
`config.go` defines `StorageConfig.Driver`, but `core/cmd/oiafd/main.go:48`
hardcodes `storage.NewMemoryStore()`. **Nothing reads the driver setting** — the
config knob is decorative. A self-hosting operator cannot plug in their own backend
today, despite the configuration implying they can.

This gates everything longitudinal:

- **Digital fencing** needs weeks of observation to build a baseline. A baseline that
  resets on restart is not a fence, it is a log viewer.
- **Continuous inventory** is worthless if scan results vanish; delta detection
  requires history.
- **An identity graph *is* persisted relationships.** There is no graph without
  durable storage, which is why M6 cannot start here.
- **The audit hash chain** currently dies on restart, which removes the entire point
  of a tamper-evident log.

**Scope.** Implement the `Store` interface (10 sub-stores, 45 methods) against a
durable backend, and make `main.go` honour `cfg.Storage.Driver`.

Two candidate approaches, in preference order:

1. **SQLite** (`modernc.org/sqlite`, pure Go — no cgo, so cross-compilation and the
   existing release matrix are unaffected). Single-file, zero-ops, appropriate for
   the single-node deployment this project actually supports.
2. **File-backed snapshot** wrapping `MemoryStore`: serialise on mutation, reload on
   boot. Much cheaper, but loses atomicity and concurrent-writer safety; acceptable
   only as an interim step and must be labelled as such.

`CGO_ENABLED=1` locally, but **do not** choose `mattn/go-sqlite3` — it would break
the pure-Go cross-build the dc-agent depends on.

**Definition of done.** `storage.driver: sqlite` in config selects the backend; a
restart preserves identities, policies, the audit chain and behavioural profiles;
`AuditEvents.Verify` still validates a chain that spans a restart; the memory driver
remains the default for tests; CI runs both.

**Explicitly out of scope.** Postgres, HA/replication, multi-node consensus. This
project has no HA story and inventing one here would be a much larger job than the
driver itself.

## 2. Inventory scanner: execute the LDAP integration test

The scanner-defect PR adds `test/ldap/` (docker harness, AD-emulation schema, 9
fixture accounts) behind the `ldap_integration` build tag. **It compiles and vets
clean but has never been run.** Until it passes, defects F3 and F4 are only
unit-proven — and those are precisely the two defects that unit tests cannot
demonstrate, because a unit test builds `*ldap.Entry` by hand and sets whatever
attributes it likes, hiding the difference between "not returned" and "not
requested".

**Known bug to fix before it can pass:** `test/ldap/testdata.ldif` creates the
groups **before** the `ou=Groups` OU they live in. LDAP has no forward references,
so those entries will fail with "no such object". Correct order is OUs → accounts →
groups. Groups must also come **last** so slapd's `memberof` overlay can
back-populate `memberOf` onto accounts that already exist; the fixture currently
sets `memberOf` directly on the user entries instead, which the overlay may or may
not preserve. Verify which mechanism actually produces `memberOf` in this image
before trusting the privileged-account assertions.

**Definition of done.** `test/ldap/run-integration.sh` passes all six integration
tests, the harness verifies the fixture loaded before running them, and a
`make test-ldap` target exists. Harness failures must remain distinguishable from
test failures and must never report silent success.

**Then:** wire `test-ldap` into CI as a non-required check first (docker-in-CI is
flaky), promote to required once stable.

## 3. AD response adapter: tests before it is ever wired

`adapters/ad-response` contains four real LDAP mutations — `disableAccount`,
`enableAccount`, `forcePasswordReset`, `removeFromGroup` — across ~365 LOC with
**zero test coverage**. `disableAccount` sets `UAC_ACCOUNTDISABLE` on a domain account. This is
the most dangerous code in the repository: an untested function that can disable
production accounts, currently saved only by the accident that nothing calls it.

**Order matters.** Test it *before* wiring it, not after. Once enforcement is live
the blast radius of a bug becomes real accounts.

**Scope.**

- Table-driven tests over the LDAP request construction (DN resolution from SID,
  UAC bit arithmetic, group membership deltas) using a mocked `ldap.Client`.
- `getUAC`/`setUAC` bit handling: preserve unrelated UAC flags, do not clobber.
- Dry-run mode must be the default and must be tested to perform no mutation.
- Failure modes: account not found, DN resolution ambiguous, connection lost
  mid-operation, permission denied. Each must return an error rather than report
  success.
- Idempotency: disabling an already-disabled account is not an error.

## 4. Wire discovery → enforcement (make fencing actually fence)

Today `discovery.Ingest` returns decisions and `/v1/ad/events` accepts events, but
nothing acts on the decision. `ad-response` already defines a `DecisionWebhook`
input type and `bus.Emitter` already POSTs hash-chained events to subscriber
webhooks with a compatible shape — so this is a wiring job, not a build.

**Scope.**

- Subscribe `ad-response` to enforcement decisions via the existing bus.
- Gate on an explicit `enforcement mode` config: `monitor` (default, log only) vs
  `response` (act). Defaulting to acting on AD accounts would be indefensible.
- Rate-limit and require confirmation for high-impact actions; disabling a Domain
  Admin because of a baseline deviation must not be automatic.
- Audit every action taken, including actions deliberately suppressed by rate limits.

**Definition of done.** An injected deviation produces a recorded enforcement
action in monitor mode and a real (dry-run) LDAP mutation in response mode, with
both paths covered by tests.

## 5. DC agent: prove it on a real domain controller

Everything in the agent is offline-tested. The `EvtSubscribe` syscall path has never
executed against `wevtapi.dll` on an actual DC.

**This is the only M4 item that cannot be done autonomously** — it needs a Windows
Server VM promoted to a domain controller. A Windows Server 2022 evaluation image is
free for 180 days, so this is a 1–2 day experiment, not a quarter of work, but it
does require provisioning outside this environment.

**Scope when available.** Promote a DC, install the agent as a service, generate real
4624/4768 events, confirm they reach `/v1/ad/events` and produce baseline updates.
Also verify service recovery behaviour (restart, crash, log rotation) and that the
agent survives a DC reboot.

**Also in scope, and not blocked on a VM:**

- **Multi-DC deduplication.** Real deployments run 2+ DCs. Without dedup, every
  authentication event is counted once per DC, which corrupts baselines silently —
  this breaks fencing *correctness*, not just efficiency. Design and implement the
  dedup key (source DC + EventRecordID) now; test it with two emulated sources.
- **ETW consumer** as an alternative ingestion path (currently RFC only).

## 6. Gateway round 10 (sibling repository)

`open-ai-gateway` PR #24 is at `afb9e96` with NB-1, NB-2 and the corrected BL-22
criterion closed. Before it can merge:

- **Re-run the non-vacuity battery at `afb9e96` and get a clean result.** The last
  run is unusable: three entries need repair (two anchors went stale when the
  `isNonStandardHeader` region was rebuilt, one mutation fails to compile), and a
  destructive `git checkout` during the diagnosis overlapped the run, so two
  "caught by FULL SUITE" verdicts were produced against a tree that did not build.
- Dispatch round-10 review only after the battery is green, so the review runs
  against a SHA whose evidence is reproducible.
- **Do not rebase while a review is frozen at a SHA.** Moving the head invalidates
  the correspondence between review evidence and merged code.

## 7. Identity graph and advanced analytics — deliberately deferred

**Recommendation: do not build the graph yet.** It is the most expensive item here
and the least defensible near-term, for three reasons: it requires durable storage
(item 1); it requires accumulated relationship history that does not exist yet; and
BloodHound's graph model has no equivalent here, so a competing implementation is a
multi-quarter project rather than a milestone.

**Cheaper path to most of the value.** Generalise the behavioural statistics the
discovery engine already computes for service accounts (`temporalRegularity`,
`sourceConsistency`, `targetConsistency`, `logonTypePurity`, `protocolPurity`) to
user accounts. That is proto-anomaly-detection on data the system already collects,
and it delivers most of the "behavioural analytics" capability at a fraction of the
cost of a graph.

**Prerequisite ordering.** Item 1 (storage) → item 2/4 (inventory + fencing
producing history) → *then* revisit the graph. Re-evaluate against integration
targets at that point rather than committing now.

## 8. Documentation accuracy — continuous

The rule adopted for this project: **if the docs underclaim, fix the docs; if they
overclaim, plan the feature.** Corrections made so far:

- `docs/comparison.md` claimed the inventory scanner shipped "with unit tests" when
  it had none. Tests now exist (21 functions); the claim is true as of the
  scanner-defect PR.
- `adapters/dc-agent/README.md` claimed "8 event IDs"; the parser handles **10**
  (4624, 4625, 4648, 4672, 4768, 4769, 4771, 4776, 2887, 2889). Underclaim → fixed.
  Note the subscription default (`DC_AGENT_EVENT_IDS`) still lists 8, which is
  correct: 2887/2889 are parsed when present but not subscribed by default. The docs
  must state that distinction rather than a single number.
- `ROADMAP.md` claimed ticket revocation. Overclaim → moved to planned work (see M4
  correction above).

Still outstanding:

- Document the two **fail-opens** the scanner tests pin deliberately, so nobody
  "fixes" them by accident or, worse, relies on the current behaviour: an unparseable
  `userAccountControl` reports `Enabled=true`, and `extractOU` truncates an OU whose
  name contains an escaped comma.
- Document the honest residual cost of the gateway's surgical header sweep: a
  legitimate correlation id containing an `@` will be mangled and that trace link
  breaks.
- Publish a **verification status** page distinguishing "tested offline" from "proven
  against real infrastructure". Most of this project is the former, and the
  distinction is the difference between a demo and a partner conversation.

## 9. Repository hygiene

- Eight open Dependabot PRs (actions + `golang.org/x` modules) need triage; several
  are stale relative to current `main`.
- Five adapter directories ship in the public tree containing only a README
  placeholder. Either give each a stub that fails loudly with a "not implemented"
  message, or remove them and list them here as planned. Shipping empty directories
  invites the assumption that something exists.
- `enforce_admins: false` on both `main` branches means an admin can merge without
  checks passing. Revisit once the required-check set is stable.
