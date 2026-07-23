# Risk Engine

The risk engine assigns a 0–100 risk score to every access request based on
contextual signals. The score influences the final decision alongside policy.

## Rules and Scoring

| Signal | Points | Reason Tag |
|--------|--------|------------|
| Privileged identity or Admins/Domain Admins group | +25 | `privileged_group` |
| Resource sensitivity: high | +20 | `resource_sensitivity_high` |
| Resource sensitivity: critical | +30 | `resource_sensitivity_critical` |
| No recent MFA | +15 | `no_recent_mfa` |
| Geo mismatch (source vs. usual) | +30 | `geo_mismatch` |
| NTLM protocol | +20 | `weak_protocol_ntlm` |
| Cleartext LDAP simple bind | +30 | `cleartext_ldap_bind` |
| Service account interactive logon | +60 | `service_account_interactive` |
| Unmanaged device | +15 | `unmanaged_device` |
| Non-compliant device | +25 | `noncompliant_device` |
| Bad IP reputation | +40 | `bad_ip_reputation` |
| Unknown IP reputation | +5 | `unknown_ip_reputation` |

The score is capped at 100.

## Risk Levels

| Level | Score Range (default) | Effect on Decision |
|-------|-----------------------|--------------------|
| low | 0–24 | No override |
| elevated | 25–49 | No override |
| high | 50–74 | No override |
| very_high | 75–89 | Escalate to `challenge` (unless already `deny`) |
| critical | 90–100 | Override to `deny` |

Thresholds are configurable via `risk.thresholds` in the YAML config or
environment.

## Evaluation Flow

1. The risk engine runs first and produces a `RiskResult` (score, level, reasons).
2. The policy engine runs and produces a `PolicyDecision`.
3. If risk level is `critical`, the final decision is forced to `deny`.
4. If risk level is `very_high` and the policy did not deny, the decision is
   escalated to `challenge`.
5. Risk reasons are appended to the policy reasons in the response.

## Future: ML-Based Scoring

The rule engine is deterministic and auditable. A future version may add an
ML-based scoring layer that:
- Trains on historical access patterns
- Detects anomalous behavior (impossible travel, unusual hours)
- Feeds a supplementary score into the same threshold framework

The `risk.Engine` interface is designed to allow swapping implementations.
