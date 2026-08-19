#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

SERVER_ADDR="127.0.0.1:18080"
SERVER_URL="http://${SERVER_ADDR}"
ADMIN_TOKEN="e2e-test-admin-token-$(date +%s)"
ADAPTER_TOKEN="e2e-test-adapter-token-$(date +%s)"
SERVER_PID=""
LOG_FILE=$(mktemp)
TOTP_SECRET_FILE=$(mktemp)

cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if [ -f "$LOG_FILE" ]; then
        rm -f "$LOG_FILE"
    fi
    if [ -f "$TOTP_SECRET_FILE" ]; then
        rm -f "$TOTP_SECRET_FILE"
    fi
}
trap cleanup EXIT

fail() {
    echo "FAIL: $1" >&2
    echo "--- Server logs ---" >&2
    cat "$LOG_FILE" >&2
    exit 1
}

echo "=== OIAF E2E Test ==="

echo "[1/14] Building binaries..."
cd "$ROOT_DIR"
go build -o /tmp/oiafd-e2e ./core/cmd/oiafd || fail "build oiafd"
go build -o /tmp/oiafctl-e2e ./cli/oiafctl || fail "build oiafctl"
go build -o /tmp/oiaf-pam-helper-e2e ./adapters/pam/oiaf-pam-helper || fail "build pam helper"

echo "[2/14] Starting server on ${SERVER_ADDR}..."
OIAF_LISTEN_ADDR="$SERVER_ADDR" \
OIAF_ADMIN_TOKEN="$ADMIN_TOKEN" \
OIAF_ADAPTER_TOKEN="$ADAPTER_TOKEN" \
OIAF_LOG_LEVEL=debug \
OIAF_LOG_FORMAT=text \
OIAF_UI_ENABLED=true \
OIAF_METRICS_ENABLED=true \
/tmp/oiafd-e2e > "$LOG_FILE" 2>&1 &
SERVER_PID=$!

sleep 2

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    fail "server failed to start"
fi

echo "[3/14] Checking health..."
HEALTH=$(curl -s "${SERVER_URL}/healthz")
echo "$HEALTH" | grep -q "ok" || fail "health check failed: $HEALTH"

echo "[4/14] Creating identity..."
IDENTITY_RESP=$(curl -s -X POST "${SERVER_URL}/v1/identities" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"username":"e2e-user","type":"person","groups":["Admins"],"privileged":true}')
IDENTITY_ID=$(echo "$IDENTITY_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null) || fail "create identity failed: $IDENTITY_RESP"
echo "  Identity ID: $IDENTITY_ID"

echo "[5/14] Enrolling TOTP..."
ENROLL_RESP=$(curl -s -X POST "${SERVER_URL}/v1/identities/${IDENTITY_ID}/factors/totp/enroll" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json")
FACTOR_ID=$(echo "$ENROLL_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['factor_id'])" 2>/dev/null) || fail "enroll failed: $ENROLL_RESP"
TOTP_SECRET=$(echo "$ENROLL_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['secret'])" 2>/dev/null) || fail "no secret in enroll response: $ENROLL_RESP"
echo "  Factor ID: $FACTOR_ID"

echo "[6/14] Generating TOTP code and activating..."
TOTP_CODE=$(/tmp/oiafctl-e2e --server "$SERVER_URL" --token "$ADMIN_TOKEN" totp code --secret "$TOTP_SECRET" 2>/dev/null | grep -oE '[0-9]{6}' | head -1)
if [ -z "$TOTP_CODE" ]; then
    TOTP_CODE=$(go run ./tools/simulator totp-code --secret "$TOTP_SECRET" 2>/dev/null | grep -oE '[0-9]{6}' | head -1)
fi
[ -n "$TOTP_CODE" ] || fail "could not generate TOTP code"

ACTIVATE_RESP=$(curl -s -X POST "${SERVER_URL}/v1/identities/${IDENTITY_ID}/factors/totp/activate" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"factor_id\":\"${FACTOR_ID}\",\"code\":\"${TOTP_CODE}\"}")
echo "$ACTIVATE_RESP" | grep -qi "error" && fail "activation failed: $ACTIVATE_RESP"
echo "$TOTP_SECRET" > "$TOTP_SECRET_FILE"
chmod 600 "$TOTP_SECRET_FILE"
echo "  TOTP activated"

echo "[7/14] Creating policies..."
curl -s -X POST "${SERVER_URL}/v1/policies" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "id": "e2e-require-mfa-ssh",
        "description": "E2E test policy",
        "enabled": true,
        "priority": 100,
        "effect": "challenge",
        "conditions": {"all": [{"path": "resource.type", "op": "eq", "value": "ssh"}, {"path": "identity.groups", "op": "contains", "value": "Admins"}]},
        "challenge": {"methods": ["totp"]}
    }' > /dev/null || fail "create challenge policy failed"
curl -s -X POST "${SERVER_URL}/v1/policies" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "id": "e2e-allow-ssh-users",
        "description": "E2E test policy: allow plain users on ssh",
        "enabled": true,
        "priority": 200,
        "effect": "allow",
        "conditions": {"all": [{"path": "resource.type", "op": "eq", "value": "ssh"}, {"path": "identity.groups", "op": "contains", "value": "users"}]}
    }' > /dev/null || fail "create allow policy failed"

echo "[8/14] Sending access evaluation..."
EVAL_RESP=$(curl -s -X POST "${SERVER_URL}/v1/access/evaluate" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "identity": {"username": "e2e-user", "groups": ["Admins"], "type": "person"},
        "resource": {"type": "ssh", "name": "test-server", "sensitivity": "high"},
        "protocol": {"name": "ssh"},
        "source": {"ip": "10.0.0.1"},
        "device": {"managed": true, "compliant": true},
        "context": {"mfa_recent": false, "interactive": true}
    }')
DECISION=$(echo "$EVAL_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['decision'])" 2>/dev/null) || fail "evaluate failed: $EVAL_RESP"
CHALLENGE_ID=$(echo "$EVAL_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['challenge']['id'])" 2>/dev/null) || fail "no challenge in response: $EVAL_RESP"
echo "  Decision: $DECISION, Challenge: $CHALLENGE_ID"
[ "$DECISION" = "challenge" ] || fail "expected challenge decision, got: $DECISION"

echo "[9/14] Verifying challenge with TOTP..."
TOTP_CODE2=$(/tmp/oiafctl-e2e --server "$SERVER_URL" --token "$ADMIN_TOKEN" totp code --secret "$TOTP_SECRET" 2>/dev/null | grep -oE '[0-9]{6}' | head -1)
if [ -z "$TOTP_CODE2" ]; then
    TOTP_CODE2=$(go run ./tools/simulator totp-code --secret "$TOTP_SECRET" 2>/dev/null | grep -oE '[0-9]{6}' | head -1)
fi
[ -n "$TOTP_CODE2" ] || fail "could not generate second TOTP code"

VERIFY_RESP=$(curl -s -X POST "${SERVER_URL}/v1/challenge/${CHALLENGE_ID}/verify" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"method\":\"totp\",\"code\":\"${TOTP_CODE2}\"}")
STATUS=$(echo "$VERIFY_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null) || fail "verify failed: $VERIFY_RESP"
echo "  Challenge status: $STATUS"
[ "$STATUS" = "approved" ] || fail "expected approved, got: $STATUS"

echo "[10/14] Verifying audit chain..."
AUDIT_RESP=$(curl -s "${SERVER_URL}/v1/audit/verify" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}")
echo "$AUDIT_RESP" | grep -q "true" || fail "audit verification failed: $AUDIT_RESP"
echo "  Audit chain valid"

echo "[11/14] PAM helper: allow path (users group on ssh → explicit allow policy)..."
PAM_ALLOW_OUT=$(PAM_USER=plainuser PAM_SERVICE=ssh PAM_TYPE=auth PAM_TTY=/dev/null \
    OIAF_SERVER="$SERVER_URL" OIAF_ADAPTER_TOKEN="$ADAPTER_TOKEN" \
    OIAF_PAM_GROUPS=users OIAF_PAM_TOTP_FILE="" \
    /tmp/oiaf-pam-helper-e2e 2>&1); PAM_ALLOW_EXIT=$?
echo "  exit=$PAM_ALLOW_EXIT: $PAM_ALLOW_OUT"
[ "$PAM_ALLOW_EXIT" -eq 0 ] || fail "PAM helper allow path: expected exit 0, got $PAM_ALLOW_EXIT"

echo "[12/14] PAM helper: challenge path (Admins group on ssh → TOTP challenge)..."
PAM_CHAL_OUT=$(PAM_USER=e2e-user PAM_SERVICE=ssh PAM_TYPE=auth PAM_TTY=/dev/null \
    OIAF_SERVER="$SERVER_URL" OIAF_ADAPTER_TOKEN="$ADAPTER_TOKEN" \
    OIAF_PAM_GROUPS=Admins OIAF_PAM_TOTP_FILE="$TOTP_SECRET_FILE" \
    /tmp/oiaf-pam-helper-e2e 2>&1); PAM_CHAL_EXIT=$?
echo "  exit=$PAM_CHAL_EXIT: $PAM_CHAL_OUT"
[ "$PAM_CHAL_EXIT" -eq 0 ] || fail "PAM helper challenge path: expected exit 0 (approved), got $PAM_CHAL_EXIT"
echo "$PAM_CHAL_OUT" | grep -q "challenge approved" || fail "PAM helper did not log challenge approval"

echo "[13/14] PAM helper: deny path (sudo → high sensitivity, no matching policy → default deny)..."
set +e
PAM_DENY_OUT=$(PAM_USER=e2e-user PAM_SERVICE=sudo PAM_TYPE=auth PAM_TTY=/dev/null \
    OIAF_SERVER="$SERVER_URL" OIAF_ADAPTER_TOKEN="$ADAPTER_TOKEN" \
    OIAF_PAM_GROUPS=Admins OIAF_PAM_TOTP_FILE="" \
    /tmp/oiaf-pam-helper-e2e 2>&1); PAM_DENY_EXIT=$?
set -e
echo "  exit=$PAM_DENY_EXIT: $PAM_DENY_OUT"
[ "$PAM_DENY_EXIT" -eq 7 ] || fail "PAM helper deny path: expected exit 7 (PAM_AUTH_ERR), got $PAM_DENY_EXIT"

echo "[14/14] PAM helper: fail-closed and fail-open when OIAF is unreachable..."
set +e
PAM_FC_OUT=$(PAM_USER=e2e-user PAM_SERVICE=sshd PAM_TYPE=auth PAM_TTY=/dev/null \
    OIAF_SERVER="http://127.0.0.1:1" OIAF_ADAPTER_TOKEN="$ADAPTER_TOKEN" OIAF_PAM_TIMEOUT=1 OIAF_PAM_TOTP_FILE="" \
    /tmp/oiaf-pam-helper-e2e 2>&1); PAM_FC_EXIT=$?
PAM_FO_OUT=$(PAM_USER=e2e-user PAM_SERVICE=sshd PAM_TYPE=auth PAM_TTY=/dev/null \
    OIAF_SERVER="http://127.0.0.1:1" OIAF_ADAPTER_TOKEN="$ADAPTER_TOKEN" OIAF_PAM_TIMEOUT=1 \
    OIAF_PAM_FAIL_OPEN=true OIAF_PAM_TOTP_FILE="" \
    /tmp/oiaf-pam-helper-e2e 2>&1); PAM_FO_EXIT=$?
set -e
echo "  fail-closed exit=$PAM_FC_EXIT"
[ "$PAM_FC_EXIT" -eq 8 ] || fail "fail-closed: expected exit 8 (PAM_SYSTEM_ERR), got $PAM_FC_EXIT"
echo "  fail-open exit=$PAM_FO_EXIT"
[ "$PAM_FO_EXIT" -eq 0 ] || fail "fail-open: expected exit 0 (PAM_SUCCESS), got $PAM_FO_EXIT"

echo ""
echo "=== ALL E2E TESTS PASSED ==="
