# Linux SSH with MFA Step-Up

Protects SSH access to Linux servers by requiring MFA step-up authentication for sensitive resources.

## Use Case

- Admin connects via SSH to a production server
- OIAF evaluates risk based on identity, device posture, and context
- If risk exceeds threshold, MFA challenge is triggered before granting access
- Access decisions are logged for audit

## Relevant Adapters

- **PAM Adapter** — intercepts SSH authentication on the Linux host
- See `docs/adapters/pam.md` for configuration details
