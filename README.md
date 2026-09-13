![Robin TOOLS](doc/splash.jpg)

Standalone federated module for Robin Admin with its own frontend runtime and extracted backend API.

## Local usage

```bash
npm install
npm run dev
npm run build
npm run preview

cd server
npm install
npm run build
```

- Remote scope: `robinTools`
- Exposed module: `./RobinToolsApp`
- Default hosted route: `/modules/robin-tools/dns-lookup/a`
- Default local remote entry: `http://localhost:4175/modules/robin-tools/remoteEntry.js`
- Docker: `docker compose up --build` starts:
  - `robin-tools-client` on the shared Docker network (no host port is published; Robin Admin reaches it as `http://robin-tools-client/modules/robin-tools/`)
  - `robin-tools-server` on the shared Docker network for Robin Admin proxying

## Docker integration

The checked-in `docker-compose.yaml` joins the shared `suite_suite` Docker network so Robin Admin can reach the module as `http://robin-tools-client/modules/robin-tools/remoteEntry.js`.

Typical local flow:

```bash
cd ../robin-admin
docker compose up -d --build

cd ../robin-tools
docker compose up -d --build
```

Robin Admin behavior:

- the **Modules** page can show Robin Tools before Sheriff has been contacted because Robin Admin seeds local bootstrap metadata
- hosted module navigation only appears when the runtime is reachable
- when hosted, Robin Tools uses Robin Admin sidebar navigation only
- hosted navigation exposes compact **DNS Lookup**, **Mail Posture**, **Reputation**, **Mail Tests**, and **Transforms** pages with in-page tabs
- DNS Lookup includes A, AAAA, CNAME, NS, TXT, PTR, CAA, SOA, and DNSSEC evidence
- Mail Posture includes MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, DANE, BIMI, FCrDNS, and mail-service SRV checks
- **Transforms** provides browser-local text, transport, hash, JWT, and timestamp utilities; transform input is not sent to the server or saved
- Reputation includes configurable RBL and DBL providers seeded with a small curated example set
- Mail Tests includes message/header/raw-message analysis plus server port tests for mail infrastructure
- Robin Tools stores check history server-side, scoped to the administrator who performed it
- private/local network server probes are blocked by default; set `ROBIN_TOOLS_ALLOW_PRIVATE_PROBES=true` only for trusted lab deployments

## Deployment modes

Robin Tools can run two ways:

- **Module mode** (default): embedded in Robin Admin, which proxies requests, authenticates the session, and provides admin identity/RBAC context. See "Docker integration" above.
- **Standalone mode**: a single self-contained container with its own bundled PostgreSQL database and its own login, for people who want to run Robin Tools on its own — for example on an offline/local machine, or as an independent diagnostics box.

### Standalone deployment

```bash
cp .env.standalone.example .env.standalone
# edit .env.standalone: set DB_PASSWORD, MODULE_PROXY_SECRET, and
# ROBIN_TOOLS_AUTH_PASSWORD_HASH (see the comments in that file)

docker compose -f docker-compose.standalone.yaml --env-file .env.standalone up -d --build
```

This starts one `robin-tools` container (Express serving both the API under
`/api` and the built frontend at `/`) plus a private `robin-tools-db` Postgres
instance, published only on the internal Compose network. Open
`http://localhost:3003` (or the port set via `ROBIN_TOOLS_PORT`).

Standalone mode has two auth options, set via `ROBIN_TOOLS_AUTH_MODE`:

- `basic` (default, recommended): single-user HTTP Basic Auth. Generate the
  password hash with `cd server && npm run hash-password -- 'your-password'`
  and set it as `ROBIN_TOOLS_AUTH_PASSWORD_HASH`.
- `none`: no login at all. Only use this for a trusted local machine with no
  network exposure (for example, fully offline use).

For an example of installing standalone mode on a bare VPS with Nginx,
Let's Encrypt, and systemd, see `examples/ansible/`. For plain Docker Compose
examples of both deployment modes, see `examples/docker-compose/`.

## Isolation model

- Robin Admin hosts the frontend remote inside a Shadow DOM mount so Robin Tools styles stay isolated from the host UI.
- Browser requests still go to Robin Admin under `/api/modules/robin-tools/*`.
- Robin Admin authenticates the session, enforces CSRF, and proxies those requests to `robin-tools-server`.

The frontend needs no environment variables in module mode. Production
deployments declare `MODULE_PROXY_SECRET`, `DB_HOST`, `DB_PORT`, `DB_NAME`,
`DB_USER`, and `DB_PASSWORD`. `PORT`, `NODE_ENV`, `LOG_LEVEL`,
`ROBIN_PTR_RESOLVERS`, and `ROBIN_TOOLS_ALLOW_PRIVATE_PROBES` are optional.
`DEPLOYMENT_MODE` selects `module` (default) or `standalone`; standalone mode
adds `ROBIN_TOOLS_AUTH_MODE`, `ROBIN_TOOLS_AUTH_USERNAME`, and
`ROBIN_TOOLS_AUTH_PASSWORD_HASH` (see "Standalone deployment" above).

The health endpoint returns HTTP 503 until the database is reachable. MTA-STS
policy retrieval validates every redirect target and rejects private,
loopback, reserved, and otherwise non-public addresses. Server diagnostics
verify TLS trust and hostnames; certificate failures are reported as failed
checks rather than successful TLS connections.

Email diagnostic uploads accept RFC 822 `.eml` and plain-text files. Outlook
binary `.msg` files are not supported.

## License

Apache 2.0 - See [LICENSE](LICENSE)

- [Contributing](contributing.md)
- [Code of conduct](code_of_conduct.md)
