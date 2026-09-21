#!/usr/bin/env bash
# oiaf-pam-field-test.sh — prove the helper works on a real PAM stack.
#
# Run on the client host AFTER `make install-pam`, with a test user and a
# reachable OIAF server. Safe: it only queries, never mutates PAM config.
set -uo pipefail

TEST_USER="${1:-}"
[ -n "$TEST_USER" ] || { echo "usage: $0 <test-user>" >&2; exit 1; }

# Binary: installed path first, repo build as fallback (dev runs).
HELPER="${OIAF_PAM_HELPER:-/usr/local/bin/oiaf-pam-helper}"
if [ ! -x "$HELPER" ] && [ -x "$(dirname "$0")/../../bin/oiaf-pam-helper" ]; then
  HELPER="$(dirname "$0")/../../bin/oiaf-pam-helper"
fi
[ -x "$HELPER" ] || { echo "helper not found: $HELPER (run make build, or install)" >&2; exit 1; }
echo "helper: $HELPER"

pass=0; fail=0
check() { # name expected actual
  if [ "$2" = "$3" ]; then echo "  PASS  $1 (exit $3)"; pass=$((pass+1));
  else echo "  FAIL  $1 (expected $2, got $3)"; fail=$((fail+1)); fi
}
check_msg() { # name needle haystack
  if printf '%s' "$3" | grep -q "$2"; then echo "  PASS  $1 (reason: $2)"; pass=$((pass+1));
  else echo "  FAIL  $1 (output did not mention '$2'): $3"; fail=$((fail+1)); fi
}

# A dummy adapter token is REQUIRED for checks that claim to test an unreachable
# server. Without one the helper fails closed earlier ("no adapter token
# configured") and never dials — so the exit code 8 would pass the assertion
# while the server-unreachable path was never exercised. Both cases return 8,
# which is exactly how a vacuous check hides.
DUMMY_TOKEN="${OIAF_PAM_TEST_TOKEN:-local-field-test-cred}"

echo "1) direct invocation (no PAM env) — should be a clean pass-through or usage error:"
OUT=$($HELPER 2>&1); RC=$?
echo "   exit=$RC out=$OUT"
[ "$RC" -ne 1 ] && { echo "  PASS  helper runs (exit $RC)"; pass=$((pass+1)); } || { echo "  FAIL  helper crashed"; fail=$((fail+1)); }

echo "2) with PAM env + adapter token, no server reachable — fail-closed expected (exit 8):"
OUT=$(PAM_USER="$TEST_USER" PAM_SERVICE=ssh PAM_TYPE=auth PAM_TTY=/dev/null \
      OIAF_SERVER=http://127.0.0.1:1 OIAF_ADAPTER_TOKEN="$DUMMY_TOKEN" OIAF_PAM_TIMEOUT=1 OIAF_PAM_TOTP_FILE="" \
      $HELPER 2>&1); RC=$?
echo "   exit=$RC out=$OUT"
check "fail-closed when OIAF unreachable" 8 "$RC"
# Exit 8 alone is ambiguous (the no-token case also returns 8), so assert the
# reason proves the server was actually dialed and refused.
check_msg "failure reason is the unreachable server, not a missing token" "evaluate failed" "$OUT"

echo "3) with PAM env + fail-open — expected exit 0:"
OUT=$(PAM_USER="$TEST_USER" PAM_SERVICE=ssh PAM_TYPE=auth PAM_TTY=/dev/null \
      OIAF_SERVER=http://127.0.0.1:1 OIAF_ADAPTER_TOKEN="$DUMMY_TOKEN" OIAF_PAM_TIMEOUT=1 OIAF_PAM_TOTP_FILE="" \
      OIAF_PAM_FAIL_OPEN=true $HELPER 2>&1); RC=$?
echo "   exit=$RC out=$OUT"
check "fail-open when OIAF unreachable" 0 "$RC"

echo "3b) with PAM env but NO adapter token — fail-closed expected (exit 8):"
# Separate, explicit coverage of the path checks 2/3 used to hit by accident.
OUT=$(env -u OIAF_ADAPTER_TOKEN PAM_USER="$TEST_USER" PAM_SERVICE=ssh PAM_TYPE=auth PAM_TTY=/dev/null \
      OIAF_SERVER=http://127.0.0.1:1 OIAF_PAM_TIMEOUT=1 OIAF_PAM_TOTP_FILE="" \
      $HELPER 2>&1); RC=$?
echo "   exit=$RC out=$OUT"
check "fail-closed when no adapter token" 8 "$RC"
check_msg "failure reason is the missing adapter token" "no adapter token configured" "$OUT"

echo "4) non-auth PAM type (account) — passthrough, exit 0:"
OUT=$(PAM_USER="$TEST_USER" PAM_SERVICE=ssh PAM_TYPE=account PAM_TTY=/dev/null \
      OIAF_SERVER=http://127.0.0.1:1 $HELPER 2>&1); RC=$?
echo "   exit=$RC out=$OUT"
check "account type passthrough" 0 "$RC"

echo
echo "5) live PAM test (requires an active OIAF server + token in /etc/oiaf/pam-env):"
echo "   In another shell, watch:  journalctl -u oiafd -f"
echo "   Then run:   su - $TEST_USER -c 'echo pam-ok'"
echo "   Expected:   'pam-ok' after (possibly) a TOTP prompt, and an"
echo "               access.decided event on the OIAF side."
echo
echo "RESULT: $pass passed, $fail failed (checks 1-4 are offline)"
[ "$fail" -eq 0 ]