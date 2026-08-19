#!/usr/bin/env bash
# oiaf-pam-install.sh — install the PAM helper on a Linux client host.
#
# Usage (on the target host, as root):
#   ./oiaf-pam-install.sh <path-to-oiaf-pam-helper-binary>
#
# What it does:
#   1. Installs the helper to /usr/local/bin/oiaf-pam-helper (0755, root).
#   2. Creates /etc/oiaf/pam-env (0600) if absent — you must fill in the
#      adapter token; the file is never printed to stdout.
#   3. Drops a PAM fragment /etc/pam.d/oiaf-pam.conf with [Default]=env so
#      the helper reads its config from the env file.
#   4. Shows the exact line to add to /etc/pam.d/sshd (or sudo/login).
#
# It does NOT edit /etc/pam.d/* files — you decide when OIAF is in the chain.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then echo "run as root" >&2; exit 1; fi
BIN="${1:-}"
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
  echo "usage: $0 <path-to-oiaf-pam-helper-binary>" >&2
  exit 1
fi

install -m 0755 -o root -g root "$BIN" /usr/local/bin/oiaf-pam-helper

mkdir -p /etc/oiaf
chmod 700 /etc/oiaf
if [ ! -f /etc/oiaf/pam-env ]; then
  cat > /etc/oiaf/pam-env <<'ENVEOF'
# OIAF PAM helper environment. 0600 root:root. Keep the token secret.
OIAF_SERVER=http://127.0.0.1:8080
# OIAF_PAM_TIMEOUT=5
# OIAF_PAM_FAIL_OPEN=false
# OIAF_PAM_GROUPS=
OIAF_ADAPTER_TOKEN=__FILL_ME__
ENVEOF
  chmod 0600 /etc/oiaf/pam-env
  echo "created /etc/oiaf/pam-env — set OIAF_ADAPTER_TOKEN (and OIAF_SERVER if remote)"
fi

cat > /etc/pam.d/oiaf-pam.conf <<'PAMCONF'
# OIAF PAM hook (loaded via @include from /etc/pam.d/<service>).
# [Default]=env makes PAM read /etc/oiaf/pam-env before invoking the helper.
auth    [success=ok default=ignore]  pam_env.so readenv=1 envfile=/etc/oiaf/pam-env
auth    [success=ok default=ignore]  pam_exec.so expose_authtok /usr/local/bin/oiaf-pam-helper
PAMCONF
chmod 0644 /etc/pam.d/oiaf-pam.conf

cat <<'EOF'
Installed. Two steps remain, by you (lockout risk — do this with a root shell open):

  1. Edit /etc/oiaf/pam-env: set OIAF_SERVER and OIAF_ADAPTER_TOKEN.
  2. Add this line to /etc/pam.d/sshd (or sudo / login), ABOVE the existing
     auth stack, while keeping a fallback:

       @include oiaf-pam.conf

  3. Test: ssh a test user; watch the helper output (it logs to stderr,
     which sshd captures) and check `journalctl -u oiafd` on the server.
  4. Rollback: remove the @include line, `pam_tally2` / re-login.

EOF