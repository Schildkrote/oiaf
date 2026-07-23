# Integration Tests

Integration tests require a running OIAF server instance. These tests are covered by the end-to-end test script at `test/e2e/e2e.sh`.

To run the full E2E suite:

```bash
./test/e2e/e2e.sh
```

The script builds the server and CLI binaries, starts the server on a test port, and exercises the full request lifecycle including identity creation, TOTP enrollment, policy evaluation, challenge verification, and audit chain validation.
