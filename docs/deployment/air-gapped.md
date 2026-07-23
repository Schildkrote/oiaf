# Air-Gapped Deployment

Notes for deploying OIAF in disconnected / air-gapped environments.

## Build Offline

- Vendor dependencies ahead of time:
  ```bash
  go mod vendor
  ```
  Build with `-mod=vendor` so no network module fetches are required.
- Build the container image on a connected host and export it:
  ```bash
  make docker-build
  docker save oiaf:latest -o oiaf.tar
  ```
- Transfer `oiaf.tar` to the air-gapped environment and `docker load -i oiaf.tar`.

## Static Binaries

- The Dockerfile builds with `CGO_ENABLED=0`, producing static binaries that run
  on the distroless base image with no external runtime dependencies.
- You can also copy the `oiafd` and `oiafctl` binaries directly to a host.

## No External Services

- The MVP runs fully self-contained with the in-memory store; no Postgres or
  Redis is strictly required for a minimal air-gapped deployment.
- For persistence without external dependencies, run a local Postgres from a
  pre-loaded image.

## Time Synchronization

- TOTP and push timestamp verification depend on accurate clocks. Ensure NTP
  (or a local time source) is synchronized across the control plane and devices.
- Adjust `push_timestamp_skew_seconds` if clock drift is expected.

## Updates

- Establish a signed, verified process for importing new releases (checksums,
  signatures).
- Verify image/binary integrity before deployment.

## Offline MFA

- For endpoints that may lose connectivity (Windows laptops, remote sites),
  review the offline MFA strategy in the
  [Windows credential provider](../adapters/windows-credential-provider.md) docs.
