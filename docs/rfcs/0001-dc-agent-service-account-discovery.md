# RFC-0001: DC Agent, Service Account Discovery, and AD Inventory

- **Status:** draft
- **Author:** OIAF Contributors
- **Created:** 2026-07-23
- **Updated:** 2026-07-23

## Summary

This RFC proposes a Domain Controller (DC) agent that monitors all Active
Directory authentication in real time using official Windows APIs, a behavioral
service account discovery engine ("digital fencing"), and an AD inventory
scanner. Together these components replace the current skeleton `ad-monitor`
adapter and remove the "no domain controller hooking" non-goal, enabling OIAF
to deliver Silverfort-equivalent capabilities: protocol-agnostic authentication
visibility, automated service account discovery, and inline enforcement —
deployable in days rather than a months-long audit.

## Motivation

### The Service Account Problem

Legacy Windows environments accumulate hundreds to thousands of service
accounts over years. These accounts are:

- Rarely documented or inventoried
- Often privileged (Domain Admin, delegation rights)
- Configured with non-expiring passwords
- Used interactively by mistake or by attackers moving laterally
- Invisible to traditional PAM tools until a manual audit is performed

Silverfort solves this with "digital fencing": passively observe all
authentication, detect accounts that behave like machines (same source, same
target, same time window, high regularity), auto-classify them as service
accounts, then confine them to their observed baseline and block deviations.
This takes days to weeks instead of a months-long consulting engagement.

### The Protocol-Agnostic Gap

The current OIAF adapter model is per-protocol: PAM for Linux SSH, RADIUS for
VPN, LDAP proxy for directory binds, Windows Credential Provider for RDP. This
means WMI, PowerShell remoting, `runas`, scheduled tasks, and arbitrary
applications authenticating via NTLM or Kerberos are invisible unless each has
its own adapter.

The German deployment context clarifies the target architecture:

> "Wir nutzen einen schlanken Windows Service, welcher wiederum offizielle
> Microsoft APIs nutzt, um jegliche Anmeldung abzufangen. Wie diese Anmeldung
> zustande gekommen ist und welche Applikation verwendet wird, ist dafür
> irrelevant. Deshalb ist uns egal wie die RDP Verbindung aufgebaut wird, es
> ist uns auch egal ob es überhaupt RDP ist. Es kann auch SSH, WMI oder jede
> andere Applikation sein, solange sie sich via LDAP(S), NTLM oder Kerberos
> am AD authentifiziert. Läuft serverseitig, aber nur auf den DCs. Und ohne
> das irgendwelche Agenten auf Applicationsservern benötigt werden."

Translation: A lean Windows Service on the DCs using official Microsoft APIs
intercepts every authentication regardless of the initiating application (RDP,
SSH, WMI, anything). No agents on application servers. Only the DCs are
instrumented.

### PAM Pre-Deployment Inventory

Before deploying a PAM solution, organisations need a complete inventory of
every account, group membership, SPN, and privilege in AD. Manual audits take
months and cost six figures. An automated AD inventory scanner that populates
the OIAF identity store on first run collapses this to hours.

## Research

### How Silverfort's Runtime Access Protection (RAP) Works

Silverfort's platform page describes a five-step inline flow:

1. User requests access from IAM infrastructure
2. IAM infrastructure forwards the request to Silverfort via RAP
3. Silverfort analyzes risk and triggers inline security controls
4. Silverfort returns a verdict to the IAM infrastructure
5. IAM infrastructure grants or denies access

Key design principle: Silverfort operates **within** the IAM infrastructure's
existing extension points. It does not inject into LSASS or hook kernel
credential handling. For Active Directory specifically, the relevant extension
points are:

| Protocol | Extension Point | Mechanism |
|----------|----------------|-----------|
| RDP (NLA) | RADIUS / NPS | RADIUS proxy intercepts NLA before session |
| LDAP | LDAP proxy | Sits between client and DC |
| Kerberos | Authentication Policy Silos (Server 2012 R2+) or KDC proxy | AD-level policy or protocol proxy |
| NTLM | Network-level interception (WFP) or NPS | ALE-layer filtering by SID |
| All protocols | DC-side event monitoring | ETW / EvtSubscribe real-time |

The German description points to the last row: a DC-side service that sees
every authentication event as it is processed by the DC, regardless of the
originating protocol.

### Windows APIs for DC-Side Authentication Monitoring

#### Option A — EvtSubscribe (Windows Event Log Real-Time API)

- **API:** `EvtSubscribe()` with `EvtSubscribeToRealtimeEvents` flag
  (wevtapi.dll)
- **Provider:** `Microsoft-Windows-Security-Auditing`
  GUID `{54849625-5478-4994-A5BA-3E3B0328C30D}`
- **Latency:** Sub-second; events delivered as the DC writes them
- **Privileges:** Requires `SeSecurityPrivilege` or membership in Event Log
  Readers; no kernel driver, no LSASS modification
- **Events captured:** 4624, 4625, 4648, 4672, 4768, 4769, 4771, 4776, 2887,
  2889 — all Kerberos, NTLM, and logon events
- **Go support:** `golang.org/x/sys/windows` exposes the wevtapi.dll syscalls;
  `github.com/bi-zone/winevent` provides a higher-level wrapper
- **Verdict:** Best fit for the "lean Windows Service using official Microsoft
  APIs" description. No WEF/WEC infrastructure required. Runs entirely in
  user mode.

#### Option B — ETW (Event Tracing for Windows) Direct

- **API:** `StartTrace` / `OpenTrace` / `ProcessTrace` or real-time consumer
  session
- **Providers:**
  - `Microsoft-Windows-Kerberos` `{BBA3ADD2-C229-4CDB-AE2B-57EB6966B0C4}`
  - `Microsoft-Windows-NTLM` `{AC43300D-5FCC-4800-8E99-1BD3F85F0320}`
  - `Microsoft-Windows-Security-Auditing` (same as above)
- **Latency:** Lower than EvtSubscribe (no event log write path)
- **Privileges:** `SeSystemProfilePrivilege` or Performance Log Users group
- **Go support:** `github.com/bi-zone/etw`
- **Verdict:** Higher performance, more complex. Appropriate at very high auth
  volumes (>10k events/sec per DC). Can be added as a Phase 2 optimisation.

#### Option C — LSA Notification Package

- **API:** Register a DLL via
  `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages`
- **Callback:** `LsaApLogonUserEx2` called for every interactive and network
  logon
- **Can deny:** Return `STATUS_ACCOUNT_RESTRICTION` to block a logon
- **Risk:** Runs inside LSASS; a crash takes down the DC. Requires code signing
  and extensive testing.
- **Verdict:** Too risky for an OSS project. Explicitly rejected.

#### Option D — Custom Security Support Provider (SSP)

- **API:** Register a custom SSP DLL via
  `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`
- **Callback:** `SpAcceptCredentials` / `SpAcceptLsaModeContext`
- **Risk:** Runs inside LSASS. Same crash risk as Option C.
- **Verdict:** Rejected for the same reasons.

#### Enforcement: WFP (Windows Filtering Platform)

- **API:** `FwpmEngineOpen`, `FwpsCalloutRegister0`, `FwpmFilterAdd`
- **Layer:** ALE (Application Layer Enforcement) — can filter by user SID,
  process, protocol, source/destination IP and port
- **Requires:** A kernel-mode callout driver (C/C++ or Rust) for inline
  inspection; user-mode management API for adding/removing filters
- **Precedent:** Windows Firewall with Advanced Security is built on WFP
- **Verdict:** The correct mechanism for inline network-level blocking on the
  DC. Phase 3 component. Does not touch LSASS or credential material.

#### Enforcement: AD Response Actions (LDAP)

- **Mechanism:** LDAPS writes to the DC: disable account
  (`userAccountControl |= 0x0002`), force password reset, remove group
  membership, revoke Kerberos tickets (via `msDS-User-Account-Control-Computed`
  or `klist`/`ktpass` on the DC)
- **Privileges:** Requires a highly privileged service account (Account
  Operators or delegated OU control)
- **Verdict:** Phase 2 enforcement. Lower risk than WFP. Already scaffolded in
  the `ad-response` adapter README.

### Service Account Discovery: Digital Fencing Algorithm

The core behavioural insight: service accounts authenticate with high temporal
and spatial regularity. Humans do not.

**Feature extraction per account (sliding window, default 30 days):**

| Feature | Signal | Service account indicator |
|---------|--------|--------------------------|
| Time-of-day histogram entropy | When does it authenticate? | Low entropy (same hours daily) |
| Day-of-week histogram entropy | Which days? | Low entropy (same days) |
| Source IP cardinality | How many distinct sources? | 1–2 (fixed server) |
| Target service cardinality | How many distinct targets? | 1–3 (fixed application) |
| Logon type distribution | Interactive (2) vs network (3) vs batch (4)? | Exclusively type 3 or 4 |
| Protocol distribution | Kerberos vs NTLM vs LDAP | Single protocol |
| Inter-arrival time CV | Regularity of intervals | Low coefficient of variation |
| Session duration variance | How long do sessions last? | Very low variance |

**AD attribute signals (static, from LDAP):**

| Attribute | Signal |
|-----------|--------|
| `servicePrincipalName` present | SPN-bearing account |
| `userAccountControl` & `TRUSTED_FOR_DELEGATION` | Delegation-enabled |
| `userAccountControl` & `DONT_EXPIRE_PASSWORD` | Non-expiring password |
| `pwdLastSet` age | Password age |
| `msDS-GroupMSAMembership` | gMSA (already a managed service account) |
| `lastLogonTimestamp` staleness | Dormant account |

**Classification:**

```
score = w1 * temporal_regularity
      + w2 * source_consistency
      + w3 * target_consistency
      + w4 * logon_type_purity
      + w5 * ad_attribute_signals

if score > threshold:
    classify as service_account
    generate baseline (allowed sources, targets, time windows)
    auto-tag in OIAF identity store
```

Default weights and threshold are configurable. Initial classification
requires a minimum observation window (default: 7 days) to avoid false
positives from new accounts.

**Baseline enforcement (digital fencing):**

Once classified, the account's observed pattern becomes its policy:

- Allowed source IPs / subnets
- Allowed target services / SPNs
- Allowed time windows (e.g., 02:00–04:00 UTC daily)
- Allowed logon types (network only)
- Allowed protocols (Kerberos only)

Any deviation triggers an OIAF `challenge` or `deny` decision via the existing
policy engine. The existing `deny-service-account-interactive-logon.json`
policy becomes automatically applicable to every discovered service account.

## Proposal

### Component 1: DC Agent (`adapters/dc-agent`)

A Windows Service written in Go that runs on each Domain Controller.

**Responsibilities:**

1. Subscribe to real-time security events via `EvtSubscribe`
   (`EvtSubscribeToRealtimeEvents`) on the
   `Microsoft-Windows-Security-Auditing` provider.
2. Filter for authentication-relevant event IDs:
   4624, 4625, 4648, 4672, 4768, 4769, 4771, 4776, 2887, 2889.
3. Parse each event's XML payload into a normalised `ADAuthEvent` struct.
4. Batch events and forward them to OIAF core via a new
   `POST /v1/ad/events` endpoint (adapter SDK).
5. Receive risk decisions back; log them to the OIAF audit store.
6. Optionally trigger AD response actions (Phase 2) or WFP filter updates
   (Phase 3) based on OIAF decisions.
7. Run an initial AD inventory scan on startup (see Component 3).

**Data structures (new types in `core/internal/types`):**

```go
type ADAuthEvent struct {
    EventID       int       `json:"event_id"`
    Timestamp     time.Time `json:"timestamp"`
    AccountName   string    `json:"account_name"`
    AccountDomain string    `json:"account_domain"`
    AccountSID    string    `json:"account_sid"`
    LogonType     int       `json:"logon_type"`
    LogonProcess  string    `json:"logon_process"`
    AuthPackage   string    `json:"auth_package"`
    SourceIP      string    `json:"source_ip"`
    SourcePort    int       `json:"source_port"`
    TargetServer  string    `json:"target_server"`
    TargetSPN     string    `json:"target_spn"`
    Status        string    `json:"status"`
    SubStatus     string    `json:"sub_status"`
    DCName        string    `json:"dc_name"`
}

type ADInventoryRecord struct {
    SID                string    `json:"sid"`
    SamAccountName     string    `json:"sam_account_name"`
    DisplayName        string    `json:"display_name"`
    ObjectClass        string    `json:"object_class"`
    UserAccountControl int       `json:"user_account_control"`
    SPNs               []string  `json:"spns,omitempty"`
    MemberOf           []string  `json:"member_of,omitempty"`
    LastLogonTimestamp time.Time `json:"last_logon_timestamp"`
    PwdLastSet         time.Time `json:"pwd_last_set"`
    Enabled            bool      `json:"enabled"`
    OU                 string    `json:"ou"`
}
```

**New API endpoint:**

```
POST /v1/ad/events
Authorization: Bearer <adapter-token>
Content-Type: application/json

{
  "events": [ADAuthEvent, ...]
}

Response: 202 Accepted
{
  "accepted": <count>,
  "decisions": [
    {"account_sid": "...", "decision": "allow|deny|challenge|alert", "risk_score": N}
  ]
}
```

**Configuration (environment / flags):**

| Key | Description | Default |
|-----|-------------|---------|
| `OIAF_SERVER` | OIAF core base URL | `http://127.0.0.1:8080` |
| `OIAF_ADAPTER_TOKEN` | Adapter bearer token | required |
| `DC_AGENT_BATCH_SIZE` | Events per OIAF batch | `200` |
| `DC_AGENT_BATCH_INTERVAL` | Max batch flush interval | `2s` |
| `DC_AGENT_EVENT_IDS` | Comma-separated event IDs to capture | `4624,4625,4648,4672,4768,4769,4771,4776` |
| `DC_AGENT_INVENTORY_ON_START` | Run AD inventory scan on startup | `true` |
| `DC_AGENT_LDAP_URL` | LDAPS URL for inventory and response | required |
| `DC_AGENT_LDAP_BIND_DN` | Service account bind DN | required |
| `DC_AGENT_LDAP_BIND_PASSWORD` | Service account password (secret) | required |
| `DC_AGENT_ENFORCEMENT_MODE` | `monitor` / `response` / `wfp` | `monitor` |

**Go dependencies to add:**

- `golang.org/x/sys/windows` — wevtapi.dll syscalls (EvtSubscribe, EvtNext,
  EvtRender)
- `github.com/go-ldap/ldap/v3` — LDAPS for inventory and response actions

**Windows Service registration:**

The agent registers as a Windows Service via
`golang.org/x/sys/windows/svc`. It runs as `NT SERVICE\OIAFDCAgent` with
`SeSecurityPrivilege` (required for reading security events) and no other
elevated privileges in `monitor` mode.

### Component 2: Service Account Discovery Engine (`core/internal/discovery`)

A new package in OIAF core that consumes `ADAuthEvent` batches and maintains
per-account behavioural profiles.

**Storage:**

A new `BehaviouralProfile` record per account SID, stored in the OIAF store
(MemoryStore initially, PostgresStore later):

```go
type BehaviouralProfile struct {
    AccountSID          string
    SamAccountName      string
    ObservationStart    time.Time
    ObservationEnd      time.Time
    TotalAuthCount      int
    TimeOfDayHistogram  [24]int
    DayOfWeekHistogram  [7]int
    SourceIPs           map[string]int
    TargetSPNs          map[string]int
    LogonTypes          map[int]int
    AuthPackages        map[string]int
    InterArrivalTimes   []time.Duration  // rolling window, capped
    ClassificationScore float64
    Classified          bool
    ClassifiedAt        time.Time
    Baseline            *ServiceAccountBaseline
}

type ServiceAccountBaseline struct {
    AllowedSourceIPs   []string
    AllowedTargetSPNs  []string
    AllowedLogonTypes  []int
    AllowedTimeWindows []TimeWindow
    AllowedProtocols   []string
}

type TimeWindow struct {
    StartMinuteOfDay int
    EndMinuteOfDay   int
    DaysOfWeek       []int
}
```

**Classification pipeline (runs on each batch ingestion):**

1. Update the account's `BehaviouralProfile` with new events.
2. If observation window ≥ minimum (default 7 days) and not yet classified:
   compute classification score.
3. If score > threshold (default 0.80): mark `Classified = true`, generate
   `ServiceAccountBaseline` from observed patterns, upsert the OIAF
   `Identity` record with `Type = "service_account"`.
4. If already classified: compare each new event against the baseline.
   Deviations generate an OIAF `AccessRequest` with
   `identity.type = "service_account"` and `context.interactive` set
   appropriately, feeding the existing risk engine and policy engine.

**Deviation detection (digital fencing enforcement):**

For each event from a classified service account:

```
deviation = source_ip NOT IN baseline.AllowedSourceIPs
         OR target_spn NOT IN baseline.AllowedTargetSPNs
         OR logon_type NOT IN baseline.AllowedLogonTypes
         OR time NOT IN baseline.AllowedTimeWindows
         OR auth_package NOT IN baseline.AllowedProtocols

if deviation:
    → OIAF evaluate (identity.type=service_account, context.interactive=<logon_type==2>)
    → existing risk rule: service_account_interactive (+60)
    → existing policy: deny-service-account-interactive-logon
    → new policy: deny-service-account-baseline-deviation (added in this RFC)
```

**New policy example:**

```json
{
  "id": "deny-service-account-baseline-deviation",
  "description": "Deny service account auth that deviates from its observed baseline",
  "enabled": true,
  "priority": 210,
  "effect": "deny",
  "conditions": {
    "all": [
      {"path": "identity.type", "op": "eq", "value": "service_account"},
      {"path": "context.baseline_deviation", "op": "eq", "value": true}
    ]
  }
}
```

This requires adding `BaselineDeviation bool` to `AccessContext` in
`core/internal/types/types.go`.

### Component 3: AD Inventory Scanner (`core/internal/inventory`)

Runs on DC agent startup and on a configurable schedule (default: every 24h).

**LDAP queries:**

| Query | Purpose |
|-------|---------|
| `(&(objectClass=user)(objectCategory=person))` | All user accounts |
| `(&(objectClass=computer))` | All computer accounts |
| `(servicePrincipalName=*)` | All SPN-bearing accounts |
| `(&(objectClass=group)(adminCount=1))` | Privileged groups |
| `(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))` | Disabled accounts |
| `(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))` | Enabled accounts |

**Attributes retrieved per account:**

`sAMAccountName`, `displayName`, `objectSid`, `userAccountControl`,
`servicePrincipalName`, `memberOf`, `lastLogonTimestamp`, `pwdLastSet`,
`whenCreated`, `distinguishedName`, `msDS-GroupMSAMembership`

**Privileged group SIDs to flag (well-known):**

| Group | SID suffix |
|-------|-----------|
| Domain Admins | -512 |
| Enterprise Admins | -519 |
| Schema Admins | -518 |
| Administrators | -544 |
| Account Operators | -548 |
| Server Operators | -549 |
| Backup Operators | -551 |
| Print Operators | -550 |

**Output:**

- Upsert every discovered account into the OIAF identity store with correct
  `IdentityType` (`person`, `service_account` for SPN-bearing or gMSA,
  `machine` for computer accounts).
- Flag privileged accounts (`Privileged = true`).
- Populate `Groups` from `memberOf`.
- Store `lastLogonTimestamp` and `pwdLastSet` in `Attributes` for staleness
  and password-age risk rules.
- Emit an `ad_inventory_completed` audit event with summary counts.

**New risk rules to add to `core/internal/risk/engine.go`:**

| Rule | Points | Condition |
|------|--------|-----------|
| `stale_account` | +20 | `lastLogonTimestamp` > 90 days |
| `password_never_expires` | +15 | `userAccountControl` & `DONT_EXPIRE_PASSWORD` |
| `spn_bearing_unmanaged` | +25 | SPN present, not gMSA, not classified |
| `privileged_stale` | +40 | Privileged group member, last logon > 30 days |

### Component 4: AD Response Adapter (`adapters/ad-response`)

Implement the existing `ad-response` README skeleton. Consumes OIAF decisions
via webhook and performs LDAPS actions:

| Action | LDAP operation |
|--------|---------------|
| Disable account | Set `userAccountControl \|= 0x0002` |
| Enable account | Clear `userAccountControl & ~0x0002` |
| Force password reset | Set `pwdLastSet = 0` |
| Remove from group | `memberOf` delete via group DN |
| Revoke Kerberos tickets | Set `msDS-User-Account-Control-Computed` or call `klist -li 0x3e7 purge` on DC |

All actions require `AD_DRY_RUN=true` by default. Every action is written to
the OIAF audit log before execution.

### Component 5: WFP Enforcement Driver (Phase 3, separate repo)

A kernel-mode WFP callout driver (Rust or C) that:

- Registers at the ALE layer (`FWPM_LAYER_ALE_AUTH_CONNECT_V4`,
  `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4`)
- Receives filter updates from the DC agent's user-mode management process
- Blocks connections matching a denied SID + source IP + protocol tuple
- Reports blocked attempts back to the DC agent for audit

This is a separate repository and build pipeline (WDK required). The DC agent
communicates with it via a named pipe or local RPC.

### Non-Goal Replacement

**Remove from README.md:**

```
- No domain controller hooking
```

**Replace with:**

```
## DC-Side Monitoring Scope

- Authentication monitoring on DCs via official Windows APIs
  (EvtSubscribe / ETW); no WEF/WEC infrastructure required
- No LSASS injection, no kernel credential interception,
  no modification of SAM or Kerberos/NTLM protocol implementations
- Inline enforcement via AD response actions (LDAPS) and
  WFP network filtering; no LSASS-resident code
- No agents required on application servers
```

### ROADMAP Update

Replace M4 with:

```
## M4 — DC Agent and Service Account Discovery

- DC agent Windows Service (EvtSubscribe real-time auth monitoring)
- AD inventory scanner (LDAP enumeration, privileged group mapping)
- Service account behavioural discovery engine (digital fencing)
- AD response adapter (account disable, ticket revocation, group removal)
- Baseline deviation detection and policy enforcement
- WFP enforcement driver (separate repo, Phase 3)
```

## Alternatives Considered

### WEF/WEC Instead of EvtSubscribe

Windows Event Forwarding requires a dedicated collector server and WEC
infrastructure. EvtSubscribe runs directly on the DC with no additional
infrastructure. EvtSubscribe is simpler to deploy and matches the "lean
Windows Service on the DC" description. WEF/WEC remains a valid fallback for
environments where direct DC access is restricted; the DC agent can be
extended to read from a WEC as an alternative event source.

### LSA Notification Package / Custom SSP

Both run inside LSASS. A crash takes down the DC and potentially the entire
domain. Both require Authenticode signing and extensive compatibility testing
across Windows Server versions. Rejected for an OSS project where the blast
radius of a bug is unacceptable.

### RADIUS Proxy for All Enforcement

Silverfort uses RADIUS proxying for NLA-protected RDP. This works for RDP and
VPN but does not cover NTLM, LDAP, WMI, PowerShell remoting, or arbitrary
Kerberos service tickets. Insufficient for the protocol-agnostic goal.

### Pure Passive Monitoring (No Enforcement)

Monitoring-only is valuable for discovery and audit but does not deliver the
"digital fencing" enforcement that blocks deviations in real time. The phased
approach (monitor → response → WFP) allows organisations to start passive and
enable enforcement incrementally.

## Security Considerations

- The DC agent holds a highly privileged LDAP bind credential. It must be
  stored DPAPI-protected under the service account's SYSTEM profile, never in
  plaintext config files. Rotate on a 90-day cycle.
- The agent token (OIAF adapter token) grants event-ingestion rights. Scope it
  to the `adapter` RBAC role only.
- In `monitor` mode the agent is read-only. Enforcement modes (`response`,
  `wfp`) must be explicitly enabled and are audited.
- The WFP driver runs in kernel mode. It must be Authenticode-signed,
  memory-safe (Rust preferred), and fuzzed before production use.
- AD inventory data contains usernames, SIDs, group memberships, and password
  ages. Treat as sensitive PII. Encrypt at rest in the OIAF store.
- The agent must never log or transmit credential material, NTLM hashes,
  Kerberos tickets, or plaintext passwords. Event XML is parsed for metadata
  fields only.
- Fail-open vs fail-closed: in `monitor` mode the agent is passive and cannot
  block. In `response` and `wfp` modes, a lost connection to OIAF core must
  default to the last-known policy decision (cached for a configurable TTL)
  rather than allowing all traffic.
- The behavioural profile store contains authentication patterns that could
  reveal infrastructure topology. Apply the same access controls as the audit
  store.

## Compatibility

- **Backward compatible.** No existing API, type, or policy format changes are
  breaking. The new `POST /v1/ad/events` endpoint is additive.
- `AccessContext` gains one new field (`BaselineDeviation bool`). Existing
  policies that do not reference it are unaffected (zero-value is `false`).
- The `ad-monitor` adapter skeleton is replaced by `dc-agent`. The old
  `adapters/ad-monitor` directory is removed; its README content is migrated
  to `adapters/dc-agent/README.md`.
- The `ad-response` adapter README is implemented; no interface change.
- The `windows-credential-provider` adapter remains planned and independent.
  It covers interactive logon MFA on the client side; the DC agent covers
  server-side protocol-agnostic monitoring. They are complementary.

## Implementation Plan

### Phase 1 — DC Agent: Passive Monitoring (M4a, ~3 weeks)

**Milestone:** DC agent running as a Windows Service, streaming real-time auth
events to OIAF core, events visible in the audit log and admin UI.

- [ ] Add `golang.org/x/sys/windows` and `github.com/go-ldap/ldap/v3` to
      go.mod
- [ ] Implement `adapters/dc-agent/main.go`: Windows Service entrypoint
      (`golang.org/x/sys/windows/svc`)
- [ ] Implement EvtSubscribe real-time subscription
      (`adapters/dc-agent/etw.go` or `adapters/dc-agent/eventlog.go`)
- [ ] Implement event XML parsing for all 10 event IDs
      (`adapters/dc-agent/parser.go`)
- [ ] Implement batch buffering and flush to `POST /v1/ad/events`
      (`adapters/dc-agent/sender.go`)
- [ ] Add `POST /v1/ad/events` endpoint to `core/internal/api`
- [ ] Add `ADAuthEvent` type to `core/internal/types/types.go`
- [ ] Add `ADAuthEvent` ingestion to audit service
- [ ] Write unit tests for event parsing (sample XML fixtures)
- [ ] Write integration test with a mock DC event stream
- [ ] Update `adapters/dc-agent/README.md`
- [ ] Remove `adapters/ad-monitor/`

### Phase 2 — AD Inventory and Service Account Discovery (M4b, ~3 weeks)

**Milestone:** Full AD inventory in OIAF identity store on first run; service
accounts auto-discovered after 7-day observation window; baseline deviation
alerts firing.

- [ ] Implement `core/internal/inventory` package (LDAP scanner)
- [ ] Implement `core/internal/discovery` package (behavioural profiler)
- [ ] Add `BehaviouralProfile` and `ServiceAccountBaseline` types
- [ ] Add `BaselineDeviation` field to `AccessContext`
- [ ] Add new risk rules: `stale_account`, `password_never_expires`,
      `spn_bearing_unmanaged`, `privileged_stale`
- [ ] Add `deny-service-account-baseline-deviation` policy example
- [ ] Wire inventory scanner into DC agent startup
- [ ] Wire discovery engine into `POST /v1/ad/events` handler
- [ ] Add identity upsert from inventory to storage interface
- [ ] Write unit tests for classification algorithm (synthetic event streams)
- [ ] Write unit tests for baseline deviation detection
- [ ] Add admin UI view: service account inventory and classification status

### Phase 3 — AD Response Adapter (M4c, ~2 weeks)

**Milestone:** OIAF deny decisions trigger AD response actions (dry-run by
default); account disable, password reset, group removal, ticket revocation
all functional and audited.

- [ ] Implement `adapters/ad-response/main.go` (webhook consumer)
- [ ] Implement LDAPS action functions (disable, reset, group removal,
      ticket revocation)
- [ ] Implement dry-run mode with audit logging
- [ ] Implement approval gating for high-impact actions (challenge required)
- [ ] Wire DC agent to call ad-response on deny decisions
- [ ] Write integration tests against a test AD (Samba AD or Windows Server
      VM)
- [ ] Update `adapters/ad-response/README.md`

### Phase 4 — WFP Enforcement Driver (M4d, separate repo, ~6 weeks)

**Milestone:** Kernel-mode WFP callout driver blocks denied auth attempts at
the network layer on the DC; blocked attempts audited in OIAF.

- [ ] Create separate repository `oiaf/oiaf-wfp-driver`
- [ ] Implement WFP callout driver in Rust (ALE layer)
- [ ] Implement user-mode management interface (named pipe)
- [ ] Implement filter update protocol (DC agent → driver)
- [ ] Implement blocked-attempt reporting (driver → DC agent)
- [ ] Authenticode signing pipeline
- [ ] Fuzz testing (AFL / libFuzzer)
- [ ] Integration test with DC agent in `wfp` enforcement mode
- [ ] Document driver installation and recovery (safe mode disable)

### Phase 5 — ETW Optimisation and Scale (M4e, optional)

**Milestone:** Direct ETW consumer for high-volume DCs (>10k auth events/sec);
horizontal scaling across multiple DCs.

- [ ] Implement direct ETW consumer (`github.com/bi-zone/etw`)
- [ ] Add Kerberos and NTLM ETW provider subscriptions
- [ ] Implement per-DC event deduplication (same auth seen by multiple DCs)
- [ ] Implement event backpressure and at-least-once delivery guarantees
- [ ] Benchmark: 50k events/sec sustained ingestion

### Testing Strategy

- **Unit tests:** Event XML parsing, classification algorithm, baseline
  deviation detection, LDAP query construction, risk rule scoring.
- **Integration tests:** Mock DC event stream → DC agent → OIAF core → audit
  log. Use `test/e2e/e2e.sh` pattern.
- **AD integration tests:** Samba AD container or Windows Server VM for LDAP
  inventory and response action tests.
- **WFP driver tests:** Windows Server VM with WDK test harness; fuzz testing
  before any production use.
- **Chaos tests:** Kill OIAF core while DC agent is streaming; verify agent
  buffers and resumes. Kill DC agent; verify no auth is blocked in `monitor`
  mode.

## Open Questions

1. **Multi-DC deduplication:** In a multi-DC forest, the same Kerberos TGT
   request may be logged by multiple DCs. Should the discovery engine
   deduplicate by `(AccountSID, Timestamp, SourceIP, TargetSPN)` tuple, or
   accept duplicates and weight them?

2. **gMSA handling:** Group Managed Service Accounts are already managed by AD.
   Should the discovery engine skip them, or still baseline their usage for
   anomaly detection?

3. **Observation window for new accounts:** A newly created service account
   has no history. Should the engine apply a conservative default baseline
   (deny interactive logon immediately) while the observation window
   accumulates?

4. **WFP driver language:** Rust (memory-safe, no GC pauses in kernel) vs C
   (WDK-native, more examples available). Rust is preferred but requires
   `windows-drivers-rs` or manual WDK bindings.

5. **Samba AD compatibility:** Should the DC agent support Samba AD (Linux DCs)
   via a different event source (syslog / `samba-tool` audit), or is
   Windows Server DC the only supported platform?

6. **Licensing of WFP driver:** The WFP driver is a kernel component. Should it
   be AGPL-3.0-only (same as OIAF) or a separate licence given its privileged
   position?
