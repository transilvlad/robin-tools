# Docker Compose Examples

Two ways to run Robin Tools, matching the two deployment modes described in
the [repository README](../../README.md#deployment-modes):

| Directory | Mode | Use when |
|-----------|------|----------|
| `standalone/` | Standalone | You want Robin Tools on its own, with its own bundled PostgreSQL and its own login. No Robin Admin required. |
| `module/` | Module | You already run the Robin Admin suite and want Robin Tools embedded in it. |

Both examples are production-oriented: they build fixed image tags, restart
automatically, and require real secrets instead of the development defaults
used by the repository root `docker-compose.yaml`.

## Standalone

```bash
cd examples/docker-compose/standalone
cp .env.example .env
# edit .env: set ROBIN_TOOLS_DB_PASSWORD, ROBIN_TOOLS_MODULE_PROXY_SECRET,
# and (for basic auth) ROBIN_TOOLS_AUTH_PASSWORD_HASH
docker compose up -d --build
```

This starts Robin Tools and a private PostgreSQL instance. Robin Tools binds
to `127.0.0.1:3003` by default; put a reverse proxy in front of it for public
HTTPS (see `../ansible/` for a full example with Nginx and Let's Encrypt).

## Module

```bash
cd examples/docker-compose/module
cp .env.example .env
# edit .env: set ROBIN_TOOLS_DB_PASSWORD and ROBIN_TOOLS_MODULE_PROXY_SECRET
# to match your Robin Admin configuration
docker compose up -d --build
```

This joins the shared `suite_suite` Docker network (or whichever network name
you set via `ROBIN_SUITE_NETWORK`) so Robin Admin can reach Robin Tools the
same way it reaches any other module.

## Secrets

Generate strong values for anything marked `CHANGE_ME`:

```bash
openssl rand -base64 48
```

Keep the real `.env` files out of Git — both example directories ignore
`.env` and `.env.local`.

## Updates

Pull the latest repository changes, then rebuild:

```bash
docker compose up -d --build
```

Back up the `robin-tools-pgdata` volume (standalone mode) or the shared Robin
Admin database (module mode) before upgrades.
