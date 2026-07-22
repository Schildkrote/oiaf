# Windows Credential Provider Adapter

**Status: Planned**

The Windows credential provider integrates OIAF MFA into the Windows logon UI
(interactive and remote desktop) via a COM-based Credential Provider DLL.

## COM DLL Architecture

- Implemented as a **Credential Provider** COM object (replaces/extends the
  password provider) registered under
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers`.
- Implements `ICredentialProvider`, `ICredentialProviderCredential`, and related
  interfaces in C++ (or a managed wrapper).
- On credential submission, it calls the OIAF Decision API; on `challenge`, it
  presents an MFA tile (TOTP entry or push confirmation) in the logon UI.

## Code Signing

- The DLL **must be Authenticode-signed** with a trusted code-signing
  certificate; unsigned providers will not load on secure systems and trigger
  warnings.
- Protect the signing key in an HSM or secure build pipeline.
- Plan for certificate renewal and re-signing of releases.

## Offline MFA

- Windows endpoints may be offline (laptops, air-gapped sites). The provider
  needs an offline strategy:
  - Cached TOTP validation with a bounded, time-synced window.
  - A limited offline grace policy with strict bounds and post-connect sync.
  - Fail-closed vs. fail-open must be a deliberate, documented choice.
- Offline decisions must be reconciled with the audit log when connectivity
  returns.

## Warnings

- A faulty credential provider can **lock users out of Windows**, including
  administrators. Always retain a recovery path (safe mode, local admin,
  recovery console).
- Test extensively in a lab OU before deployment.
- This adapter is planned and not yet implemented.
