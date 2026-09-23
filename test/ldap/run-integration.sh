#!/usr/bin/env bash
# Start a real LDAP directory in docker, load the AD-emulation schema and test data,
# and run the inventory scanner's integration tests against it.
#
# WHY THIS EXISTS: the scanner's unit tests build *ldap.Entry values by hand, which
# cannot catch a defect where an attribute is READ but never REQUESTED (the directory
# simply does not send it) or where a value is read from a constructed attribute that
# real directories do not return. Two such defects shipped. Only a server round-trip
# observes "requested" and "returned" diverging.
#
# USAGE
#   test/ldap/run-integration.sh        # start, test, tear down
#   KEEP_UP=1 test/ldap/run-integration.sh   # leave the container running
#   LDAP_URL=ldap://host:1389 test/ldap/run-integration.sh  # use an existing server
#
# EXIT CODES: 0 = tests passed. Non-zero = tests failed OR the harness could not start
# the directory (the two are distinguished in the output; a harness failure is never
# reported as a test failure, and never as a silent success).

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

IMAGE="${LDAP_IMAGE:-osixia/openldap:1.5.0}"
CONTAINER="${LDAP_CONTAINER:-oiaf-ldap-it}"
HOST_PORT="${LDAP_PORT:-1389}"
BASE_DN="dc=corp,dc=example,dc=com"
ADMIN_DN="cn=admin,${BASE_DN}"
ADMIN_PW="test-admin-password"
SCHEMA="$(dirname "${BASH_SOURCE[0]}")/schema-ad-emulation.ldif"
TESTDATA="$(dirname "${BASH_SOURCE[0]}")/testdata.ldif"

# --- disk guard -------------------------------------------------------------
# The mutation harness aborts below 6GB free; the same floor applies here because a
# docker image plus a directory server will not fit otherwise.
free_gb=$(df -g / 2>/dev/null | tail -1 | awk '{print $4}')
if [ -n "${free_gb}" ] && [ "${free_gb}" -lt 6 ] 2>/dev/null; then
    echo "ABORT: only ${free_gb}G free on /; the docker LDAP harness needs more." >&2
    exit 2
fi

cleanup() {
    if [ "${KEEP_UP:-0}" = "1" ]; then
        echo "KEEP_UP=1: leaving ${CONTAINER} running (ldap://127.0.0.1:${HOST_PORT})"
        return
    fi
    docker rm -f "${CONTAINER}" >/dev/null 2>&1
}
trap cleanup EXIT

# --- container --------------------------------------------------------------
if [ -z "${LDAP_URL:-}" ]; then
    echo "=== starting ${IMAGE} on port ${HOST_PORT} ==="
    docker rm -f "${CONTAINER}" >/dev/null 2>&1

    # LDAP_TLS=false: the scanner's connect() only negotiates TLS for ldaps:// URLs,
    # and the test exercises the plain path. TLS coverage would need a cert fixture;
    # that is tracked separately rather than silently skipped here.
    docker run -d --name "${CONTAINER}" \
        -p "${HOST_PORT}:389" \
        -e LDAP_TLS=false \
        -e LDAP_ORGANISATION="OIAF Test Corp" \
        -e LDAP_DOMAIN="corp.example.com" \
        -e LDAP_BASE_DN="${BASE_DN}" \
        -e LDAP_ADMIN_PASSWORD="${ADMIN_PW}" \
        -e LDAP_REMOVE_CONFIG_AFTER_BOOTSTRAP=false \
        "${IMAGE}" >/dev/null
    if [ $? -ne 0 ]; then
        echo "HARNESS FAILURE: could not start the container." >&2
        exit 2
    fi

    echo -n "=== waiting for slapd"
    ready=0
    for i in $(seq 1 60); do
        if docker exec "${CONTAINER}" ldapsearch -x -H ldap://localhost:389 \
                -D "${ADMIN_DN}" -w "${ADMIN_PW}" -b "${BASE_DN}" -s base >/dev/null 2>&1; then
            ready=1; echo " ready (${i}s)"; break
        fi
        echo -n "."; sleep 1
    done
    if [ "${ready}" != "1" ]; then
        echo ""; echo "HARNESS FAILURE: slapd did not accept binds in 60s." >&2
        docker logs --tail 40 "${CONTAINER}" >&2
        exit 2
    fi

    # --- schema -------------------------------------------------------------
    # osixia/openldap uses cn=config (slapd.d), so the schema is added with
    # ldapadd against the config backend, not by dropping a file in /etc/ldap/schema.
    echo "=== loading the AD-emulation schema ==="
    if ! docker exec -i "${CONTAINER}" ldapadd -x -H ldap://localhost:389 \
            -D "cn=admin,cn=config" -w "${ADMIN_PW}" -f /dev/stdin < "${SCHEMA}" 2>&1 \
            | tee /tmp/oiaf-schema.out | tail -3; then
        echo "HARNESS FAILURE: schema load failed." >&2
        exit 2
    fi
    if grep -qi "already exists\|Invalid syntax\|ldap_add" /tmp/oiaf-schema.out; then
        echo "  (note: schema output contained a warning; see /tmp/oiaf-schema.out)"
    fi

    # --- test data ----------------------------------------------------------
    # __RECENT_FILETIME__ is substituted with a FILETIME for "now" minus 5 minutes,
    # because staleness is relative to the current time and a hardcoded "recent" value
    # would rot: in a few months the fixture accounts would all be genuinely stale and
    # TestIntegration_ScanAgainstRealDirectory would fail for a reason unrelated to the
    # code under test.
    #
    # FILETIME = (unix_seconds + 11644473600) * 10^7
    recent_ft=$(( ( $(date +%s) - 300 + 11644473600 ) * 10000000 ))
    echo "=== loading test data (recent FILETIME = ${recent_ft}) ==="
    tmp_ldif=$(mktemp)
    # OUs must be created before the entries that live in them.
    {
        cat "${TESTDATA}" | sed "s/__RECENT_FILETIME__/${recent_ft}/g"
    } > "${tmp_ldif}"

    if ! docker exec -i "${CONTAINER}" ldapadd -x -H ldap://localhost:389 \
            -D "${ADMIN_DN}" -w "${ADMIN_PW}" -f /dev/stdin < "${tmp_ldif}" 2>&1 \
            | tee /tmp/oiaf-data.out | grep -c "^adding" | sed 's/^/  entries added: /'; then
        echo "HARNESS FAILURE: test data load failed." >&2
        tail -20 /tmp/oiaf-data.out >&2
        rm -f "${tmp_ldif}"
        exit 2
    fi
    if grep -qi "ldap_add.*Already exists\|Invalid syntax\|no such object" /tmp/oiaf-data.out; then
        echo "  (warning: some entries may not have loaded; see /tmp/oiaf-data.out)"
    fi
    rm -f "${tmp_ldif}"

    export OIAF_TEST_LDAP_URL="ldap://127.0.0.1:${HOST_PORT}"
    export OIAF_TEST_LDAP_BIND_DN="${ADMIN_DN}"
    export OIAF_TEST_LDAP_BIND_PASSWORD="${ADMIN_PW}"
    export OIAF_TEST_LDAP_BASE_DN="${BASE_DN}"
fi

# --- verify the directory actually holds the fixture -------------------------
count=$(docker exec "${CONTAINER}" ldapsearch -x -H ldap://localhost:389 \
        -D "${ADMIN_DN}" -w "${ADMIN_PW}" -b "${BASE_DN}" \
        "(|(objectClass=user)(objectClass=computer))" dn 2>/dev/null \
        | grep -c "^dn:")
echo "=== directory reports ${count} user/computer entries ==="
if [ "${count}" -lt 9 ]; then
    echo "HARNESS FAILURE: expected 9 accounts, found ${count}. The schema or test" >&2
    echo "data did not load correctly, so the integration tests would fail for a" >&2
    echo "reason unrelated to the scanner. Not running them." >&2
    exit 2
fi

# --- run ----------------------------------------------------------------------
echo "=== go test -tags ldap_integration ./core/internal/inventory/ ==="
go test -count=1 -v -tags ldap_integration ./core/internal/inventory/ 2>&1 \
    | grep -E "^(=== RUN|--- PASS|--- FAIL|--- SKIP|ok|FAIL|PASS)|SUMMARY|    ldap_integration_test.go:[0-9]+:|    scanner_test.go:[0-9]+:" \
    | head -60
status="${PIPESTATUS[0]}"

echo ""
if [ "${status}" = "0" ]; then
    echo "RESULT: integration tests PASSED against a real directory server."
else
    echo "RESULT: integration tests FAILED (exit ${status})." >&2
fi
exit "${status}"
