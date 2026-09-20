# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Okta adapter: read-only System Log ingestion (`/api/v1/logs`) with stateful
  cursor, risk-signal detection (impossible travel, new geo/device, MFA
  fail/deny/fatigue, legacy auth, admin actions, auth failures), delivery to
  OIAF core via the adapter evaluate callback, rate-limit-aware pagination
  with backoff, and an offline fixture mode for CI. Not yet proven against a
  live Okta tenant.
- Initial repository scaffold
- Core MVP control plane
- CLI tool (oiafctl)
- Admin UI
- Policy engine
- Risk engine
- TOTP and push MFA
- Audit logging with hash chain
- Adapter SDK and skeletons
