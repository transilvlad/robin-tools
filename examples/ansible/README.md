# Robin Tools Ansible Example

This example deploys Robin Tools in standalone mode on an Ubuntu or Debian
host with Docker Compose, its own bundled PostgreSQL, an optional Nginx
reverse proxy, optional Let's Encrypt certificates, and Ansible Vault-backed
secrets.

It is intentionally an example playbook, not a universal production role.
Treat the defaults as a secure starting point and adapt the network, backup,
monitoring, and host hardening choices to your environment.

## What It Sets Up

- Clones this repository to the target host
- Builds and starts Robin Tools with Docker Compose using `Dockerfile.standalone`
- Runs PostgreSQL as a private Compose service on an internal-only Docker network
- Keeps database and auth secrets in a local `.env` file with `0600` mode
- Binds the Robin Tools container to `127.0.0.1` by default
- Publishes the app through Nginx
- Optionally obtains and renews Let's Encrypt certificates
- Optionally enables UFW with SSH, HTTP, and HTTPS allowed
- Fails early if production secrets still contain placeholder values

## Files

| File | Purpose |
|------|---------|
| `inventory.example.ini` | Example inventory |
| `group_vars/robin_tools.example.yml` | Non-secret settings |
| `group_vars/robin_tools.vault.example.yml` | Secret variable names for Ansible Vault |
| `site.yml` | Main playbook |
| `templates/docker-compose.yml.j2` | Production-oriented Compose file |
| `templates/env.j2` | Secret `.env` file rendered on the server |
| `templates/nginx.conf.j2` | Nginx reverse proxy |
| `templates/robin-tools.service.j2` | systemd boot integration for Compose |

## 1. Copy the Example Files

```bash
cp inventory.example.ini inventory.ini
cp group_vars/robin_tools.example.yml group_vars/robin_tools.yml
```

Edit `inventory.ini` and `group_vars/robin_tools.yml` for your host and
domain.

## 2. Create Vault Secrets

```bash
ansible-vault create group_vars/robin_tools.vault.yml
```

Use `group_vars/robin_tools.vault.example.yml` as the shape of the file.
Generate long random values before pasting them into Vault:

```bash
openssl rand -base64 48
```

At minimum, set:

```yaml
robin_tools_db_password: "replace-with-a-long-random-password"
robin_tools_module_proxy_secret: "replace-with-a-long-random-value"
robin_tools_admin_password: "replace-with-a-strong-password"
```

`robin_tools_admin_password` is only used when `robin_tools_auth_mode: basic`
(the default). The playbook's `env.j2` template turns it into a bcrypt hash
with Ansible's `password_hash` filter — the plaintext password never reaches
the server, only the resulting hash does. This requires `passlib` on the
**control node** (the machine running `ansible-playbook`, not the target
host):

```bash
pip install passlib
```

## 3. Review the Public Settings

Important settings in `group_vars/robin_tools.yml`:

- `robin_tools_domain`: the public hostname, for example `robin-tools.example.com`
- `robin_tools_admin_email`: used for Let's Encrypt registration
- `robin_tools_auth_mode`: `basic` (single-user login, recommended) or `none` (no login — trusted/offline use only)
- `robin_tools_enable_letsencrypt`: whether Ansible should request a certificate
- `robin_tools_enable_ufw`: whether Ansible should manage the firewall

By default the Robin Tools container only listens on `127.0.0.1:3003`; Nginx
is the public entry point.

## 4. Run the Playbook

```bash
ansible-playbook -i inventory.ini site.yml --ask-vault-pass
```

If you use a Vault password file:

```bash
ansible-playbook -i inventory.ini site.yml --vault-password-file ~/.ansible/robin-tools-vault
```

## 5. Operational Notes

- Back up the PostgreSQL named volume before serious production use.
- Keep `group_vars/robin_tools.vault.yml` out of Git. This repository ignores it.
- Rotate `robin_tools_admin_password` and re-run the playbook whenever it may
  have been exposed; the login has no separate reset flow.
- Keep the host OS, Docker, and Nginx patched.
- Add monitoring for container health, disk usage, and certificate expiry
  before opening a public service.

## 6. Update or Redeploy

Change `robin_tools_repo_version` to a tag, branch, or commit, then rerun:

```bash
ansible-playbook -i inventory.ini site.yml --ask-vault-pass
```

The playbook updates the checkout and runs `docker compose up -d --build`.
