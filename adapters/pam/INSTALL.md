# OIAF PAM helper — packaging for Linux hosts

Two separate concerns, two separate artifacts:

| Artifact | What it is | Where it runs |
|---|---|---|
| `oiaf-pam-helper` | a **PAM hook binary** invoked by `pam_exec.so` per auth attempt | the client host (sshd/sudo/login target), installed to `/usr/local/bin/` |
| `oiafd.service` | a **systemd unit** for the OIAF core | the OIAF server host (may be the same machine) |

The PAM helper is **not** a daemon — it has no systemd unit of its own. It is
installed by the Makefile `make install-pam` target, which also drops a
`[Default]=env` PAM fragment so the helper gets its configuration without
hard-coding secrets in `/etc/pam.d/*`.

## Quick start (server host)

```bash
# from the repo root
sudo make install        # installs oiafd + oiafctl to /usr/local/bin (see Makefile)
sudo cp deploy/systemd/oiafd.service /etc/systemd/system/
sudo mkdir -p /etc/oiaf && sudo chmod 750 /etc/oiaf
# tokens: oiafd generates .oiaf/{admin-token,adapter-token} on first start;
# copy the adapter token into the PAM env file on the client host.
sudo tee /etc/oiaf/oiafd.env >/dev/null <<'EOF'
OIAF_LISTEN_ADDR=127.0.0.1:8080
EOF
sudo systemd-daemon-reload
sudo systemctl enable --now oiafd
curl -s http://127.0.0.1:8080/healthz
```

## Quick start (client host)

```bash
# 1) build (on any host with Go 1.25+) and copy the binary, or scp it
make build
sudo scp bin/oiaf-pam-helper target:/usr/local/bin/

# 2) on the target:
sudo make install-pam          # or: sudo cp bin/oiaf-pam-helper /usr/local/bin/
sudo mkdir -p /etc/oiaf && sudo chmod 700 /etc/oiaf
sudo tee /etc/oiaf/pam-env >/dev/null <<'EOF'
OIAF_SERVER=http://127.0.0.1:8080
OIAF_ADAPTER_TOKEN=<token f