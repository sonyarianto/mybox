# MyBox

MyBox is a paper-and-sticky-notes task manager built around an infinite
canvas. It is local-first by default: the free board works offline, needs no
account, and stores work in the browser. Pro is optional and adds account-based
cloud sync across devices.

## Product

- Create spaces and arrange tasks on a tactile paper canvas.
- Keep working offline with local browser storage.
- Export and restore workspace data as JSON.
- Add an account only when you want cloud sync.
- Use Pro sync to keep spaces converged across browsers and devices.

The browser remains the local source of truth. Authenticated sync is backed by
PostgreSQL and is enabled only for accounts with an active Pro entitlement.
Local work is not deleted when an account expires or the network is unavailable.

## Stack

- Frontend: Leptos CSR, Rust/WASM, Trunk, and Tailwind CSS
- Local data and sync model: IndexedDB, Yrs, and Y-Sync
- API: Axum and SQLx
- Database: PostgreSQL
- Authentication: local email+password with opaque Postgres sessions, optional Google/GitHub OAuth
- Billing: none (every signed-in account syncs)
- Deployment: Docker Compose, Nginx, and Caddy

## Self-hosting

### Requirements

- A Linux host with Docker and Docker Compose
- A domain pointing to the host for production HTTPS
- Optional Google/GitHub OAuth client IDs and secrets for one-click sign-in

### Configure

Copy the example configuration and replace every placeholder with deployment
values:

```sh
cp .env.example .env
```

At minimum, configure the database values, `MYBOX_ALLOWED_ORIGINS`, and
`AUTH_POST_LOGIN_REDIRECT`.

Use the public HTTPS origin consistently in `AUTH_POST_LOGIN_REDIRECT` and
`MYBOX_ALLOWED_ORIGINS`. To offer Google/GitHub sign-in, register
`OAUTH_GOOGLE_REDIRECT_URI` / `OAUTH_GITHUB_REDIRECT_URI`
(`https://your-domain.example/auth/callback`) with each provider and set the
matching client IDs and secrets.

### Build and run

Build the frontend, then start PostgreSQL, the API, the static frontend, and
Caddy:

```sh
make css
cd apps/web && trunk build --release
cd ../..
docker compose --env-file .env -f deploy/docker-compose.yml up --build -d \
  postgres mybox-api mybox caddy
```

Update `deploy/caddy/Caddyfile` with your domain before starting Caddy. It
terminates HTTPS and proxies the frontend service. PostgreSQL and the API are
not exposed publicly by the compose file; the API runs on the internal Compose
network and the local frontend port is bound to loopback.

Check the deployment with:

```sh
curl -fsS https://your-domain.example/healthz
curl -fsS https://your-domain.example/readyz
```

The API runs checked-in migrations on startup. Keep the `postgres_data` volume,
and create regular encrypted PostgreSQL backups. The repository includes
`scripts/backup-postgres.sh`, `scripts/verify-postgres-backup.sh`, and
`scripts/restore-postgres.sh` for the backup workflow.

### Local development

For a local UI and API run:

```sh
docker compose -f deploy/docker-compose.yml up --build postgres mybox-api
make dev
```

The UI runs at `http://localhost:8080` and the API at `http://localhost:3000`.
For local auth testing, use the localhost URLs from `.env.example`.
OAuth providers cannot redirect to a private localhost address, so use an
HTTPS tunnel (see `make cloudflare-tunnel`) when testing Google/GitHub sign-in.

## Useful commands

```sh
make check                  # check the Rust workspace
make local-auth             # exercise local signup, sign-in, and session
make backup-restore-acceptance
```
