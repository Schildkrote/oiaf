# Windows Credential Provider Adapter

## Purpose

The Windows credential provider adapter integrates OIAF with the Windows logon
UI. Implemented as a COM DLL that implements
`ICredentialProvider` / `ICredentialProviderCredential`, it adds an OIAF
step-up or risk-based challenge to the interactive logon, RDP, and UAC flows.

## Status

Planned (M4). Documentation only — no Go code. This component is a Windows COM
DLL (C++/C# or Rust), not a Go binary.

## Architecture

```
Winlogon --> Credential Provider (COM DLL) --> OIAF core
                    |
                    +--> wraps/extends the password tile
                    +--> triggers MFA challenge on risk
```

- Registered under
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers`.
- Enumerates credentials and serializes them for Winlogon.
- Calls OIAF `/v1/access/evaluate` and `/v1/challenge/{id}/verify`.
- Can present a TOTP/push challenge tile before releasing credentials.

## Configuration

Configuration is stored in the Windows registry or a local config file under
`ProgramData\OIAF`:

| Key               | Description                        | Default        |
|-------------------|------------------------------------|----------------|
| `ServerUrl`       | OIAF core base URL                 | `http://127.0.0.1:8080` |
| `AdapterToken`    | Adapter bearer token (DPAPI-protected) | required   |
| `FailOpen`        | Allow logon on OIAF error          | `false`        |

## Security considerations

- The credential provider sees plaintext credentials — it must be code-signed
  and tamper-resistant.
- Store the adapter token protected with DPAPI under the SYSTEM account.
- Default to fail-closed; a fail-open logon path is a high-value target.
- Test extensively: a crashing provider can make Windows unbootable. Provide a
  recovery path (safe mode / registry disable).
- Sign the DLL and validate Authenticode before registration.

## Roadmap

- [ ] COM credential provider skeleton (C++/Rust)
- [ ] OIAF evaluate call during credential serialization
- [ ] TOTP/push challenge tile
- [ ] DPAPI-protected token storage
- [ ] Installer (MSI) with recovery/disable mechanism
